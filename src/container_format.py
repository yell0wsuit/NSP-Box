"""Rebuild extracted, already-decrypted title files as an emulator NSP.

No Nintendo keys, tickets, or cartridge signatures are generated or needed here.
NCA headers and sections are plaintext, with conventional PFS0/SHA256 and RomFS/IVFC.
"""
from pathlib import Path
import hashlib, struct, time, threading, stat, os
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from contextlib import contextmanager

@dataclass(frozen=True)
class FilePart:
    path: Path
    size: int

_context = threading.local()

def configure(cancel=None, progress=None):
    _context.cancel = cancel
    _context.progress = progress
    _context.source_digests = None

@contextmanager
def isolated_context():
    """Restore the caller's thread-local builder state even on cancellation."""
    previous=_context.__dict__.copy()
    try:
        yield
    finally:
        _context.__dict__.clear()
        _context.__dict__.update(previous)

def capture_sources(digests):
    _context.source_digests=digests

def checkpoint():
    event = getattr(_context, 'cancel', None)
    if event is not None and event.is_set():
        raise InterruptedError('Packaging cancelled.')

def progress(done, total):
    checkpoint()
    cb = getattr(_context, 'progress', None)
    if cb: cb(done, total)

EMPTY = 0xffffffff
def align(n, a): return (n + a - 1) // a * a
def sha(b): return hashlib.sha256(b).digest()
def pack(fmt, *v): return struct.pack('<' + fmt, *v)

class Blob:
    def __init__(self, *parts):
        self.parts = []
        for p in parts:
            if isinstance(p, Blob): self.parts.extend(p.parts)
            elif isinstance(p, FilePart): self.parts.append((p.path, p.size))
            elif isinstance(p, Path): self.parts.append((p, p.stat().st_size))
            elif isinstance(p, int):
                if p < 0: raise ValueError('Negative padding')
                if p: self.parts.append((None, p))
            elif p: self.parts.append((bytes(p), len(p)))
        self.size = sum(n for _, n in self.parts)

    def chunks(self, block=1024*1024):
        pending = bytearray()
        for source, size in self.parts:
            f = source.open('rb') if isinstance(source, Path) else None
            capture=getattr(_context,'source_digests',None)
            source_hash=hashlib.sha256() if f and capture is not None and source in capture else None
            try:
                checkpoint()
                pos = 0
                while pos < size:
                    n = min(block - len(pending), size - pos)
                    if f: b = f.read(n)
                    elif source is None: b = bytes(n)
                    else: b = source[pos:pos+n]
                    if len(b) != n: raise IOError('Source changed or short read')
                    if source_hash is not None:source_hash.update(b)
                    pos += n
                    if not pending and len(b)==block:
                        checkpoint();yield b;continue
                    pending.extend(b)
                    if len(pending) == block:
                        checkpoint()
                        yield bytes(pending); pending.clear()
            finally:
                if f: f.close()
            if source_hash is not None:capture[source]=source_hash.digest()
        if pending: yield bytes(pending)

    def read_head(self, n):
        if n<=0:return b''
        from contextlib import closing
        with closing(self.chunks(n)) as chunks:return next(chunks,b'')

    def digest(self):
        h = hashlib.sha256()
        done = 0
        for b in self.chunks(4*1024*1024):
            h.update(b); done += len(b); progress(done, self.size)
        return h.digest()

    def pad(self, a): return Blob(self, align(self.size, a)-self.size)

def filesystem(entries, hfs=False):
    entries = [(name, b if isinstance(b, Blob) else Blob(b)) for name,b in entries]
    table = b''.join(name.encode()+b'\0' for name,_ in entries)
    entry_size = 0x40 if hfs else 0x18
    table += bytes(align(0x10 + entry_size*len(entries)+len(table), 0x200 if hfs else 0x10)
                   -(0x10+entry_size*len(entries)+len(table)))
    hdr = bytearray(pack('4sIII', b'HFS0' if hfs else b'PFS0', len(entries), len(table), 0))
    name_off = 0; data_off = 0; body = []
    for name, blob in entries:
        if hfs:
            hashed_size = min(blob.size, 0x200)
            hdr.extend(pack('QQIIQ32s', data_off, blob.size, name_off, hashed_size, 0,
                            sha(blob.read_head(hashed_size))))
        else: hdr.extend(pack('QQII', data_off, blob.size, name_off, 0))
        name_off += len(name.encode())+1
        padded = blob.pad(0x200 if hfs else 0x10)
        body.append(padded); data_off += padded.size
    return Blob(hdr, table, *body)

def bucket_count(n):
    if n < 3: return 3
    if n < 19: return n | 1
    while any(n % d == 0 for d in (2,3,5,7,11,13,17)): n += 1
    return n

def name_hash(parent, name):
    h = parent ^ 123456789
    for c in name:
        h = ((h >> 5) | ((h << 27) & 0xffffffff)) ^ c
    return h

def romfs(root, manifest, notify=None):
    return _romfs(root,manifest,notify)


def romfs_indexed(files, staging, write_source, notify=None):
    """Build the same RomFS tables from an index, writing one aligned payload."""
    tree={}
    for name,source in files.items():
        checkpoint();parts=name.split('/')
        if any(p in ('','.','..') or '\\' in p or '\0' in p for p in parts):raise ValueError('Invalid indexed RomFS path')
        branch=tree
        for part in parts[:-1]:
            branch=branch.setdefault(part,{})
            if not isinstance(branch,dict):raise ValueError('RomFS path collision')
        if parts[-1] in branch:raise ValueError('RomFS path collision')
        branch[parts[-1]]=source
    return _romfs(None,None,notify,tree,staging,write_source)


def _romfs(root, manifest, notify=None, indexed=None, staging=None, write_source=None):
    dirs = []; files = []
    def visit(path, parent):
        checkpoint()
        d = dict(path=path, name=path.name.encode() if parent is not None else b'', parent=parent,
                 dirs=[], files=[])
        dirs.append(d)
        with os.scandir(path) as scanned:children=sorted(scanned,key=lambda e:e.name.encode())
        for entry in children:
            p=Path(entry.path);info=entry.stat(follow_symlinks=False)
            if entry.is_symlink() or getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                raise ValueError('Linked folders/files are not supported: '+str(p))
            if entry.is_dir(follow_symlinks=False): d['dirs'].append(visit(p,d))
            elif entry.is_file(follow_symlinks=False):
                f = dict(path=p, name=p.name.encode(), parent=d, size=info.st_size)
                files.append(f); d['files'].append(f)
                if notify and len(files)%1024==0:notify(len(files))
        return d
    def visit_index(branch,parent,name=''):
        checkpoint()
        d=dict(name=name.encode(),parent=parent,dirs=[],files=[]);dirs.append(d)
        for name,source in sorted(branch.items(),key=lambda entry:entry[0].encode()):
            checkpoint()
            if isinstance(source,dict):d['dirs'].append(visit_index(source,d,name))
            else:
                f=dict(name=name.encode(),parent=d,size=source.size,source=source)
                files.append(f);d['files'].append(f)
                if notify and len(files)%1024==0:notify(len(files))
        return d
    if indexed is None:visit(root,None)
    else:visit_index(indexed,None)
    doff = 0; foff = 0; dataoff = 0
    for d in dirs:
        d['off'] = doff; doff += 0x18+align(len(d['name']),4)
    for i,f in enumerate(files):
        if i%1024==0:checkpoint()
        f['off'] = foff; foff += 0x20+align(len(f['name']),4)
        f['dataoff'] = align(dataoff,0x10); dataoff = f['dataoff']+f['size']
    # Link siblings in linear time; repeated scans here used to be quadratic.
    for d in dirs:
        for children in (d['dirs'],d['files']):
            for i,child in enumerate(children):
                child['sibling']=children[i+1]['off'] if i+1<len(children) else EMPTY
    dh = [EMPTY]*bucket_count(len(dirs)); fh = [EMPTY]*bucket_count(len(files))
    dt = bytearray(doff); ft = bytearray(foff)
    for d in dirs:
        parent = d['parent'];sib=d.get('sibling',EMPTY)
        par = parent['off'] if parent else 0
        bucket = name_hash(par,d['name'])%len(dh)
        entry = pack('IIIIII',par,sib,d['dirs'][0]['off'] if d['dirs'] else EMPTY,
                     d['files'][0]['off'] if d['files'] else EMPTY,dh[bucket],len(d['name']))
        dh[bucket] = d['off']; pos=d['off']; dt[pos:pos+0x18]=entry
        dt[pos+0x18:pos+0x18+len(d['name'])]=d['name']
    payload=[]; pos=0
    for f in files:
        if manifest is None or len(manifest)%1024==0:checkpoint()
        sib=f['sibling']
        par=f['parent']['off']; bucket=name_hash(par,f['name'])%len(fh)
        entry=pack('IIQQII',par,sib,f['dataoff'],f['size'],fh[bucket],len(f['name']))
        fh[bucket]=f['off']; off=f['off'];ft[off:off+0x20]=entry
        ft[off+0x20:off+0x20+len(f['name'])]=f['name']
        if indexed is None:
            payload.extend([f['dataoff']-pos,FilePart(f['path'],f['size'])]);pos=f['dataoff']+f['size']
            manifest.append({'path':str(f['path']), 'size':f['size'], 'romfs_offset':f['dataoff']})
    if indexed is not None:
        with staging.open('xb',buffering=4*1024*1024) as out:
            for f in files:
                checkpoint();out.write(bytes(f['dataoff']-pos))
                write_source(f['source'],out)
                pos=f['dataoff']+f['size']
                if out.tell()!=pos:raise IOError('Indexed RomFS source length mismatch')
        payload=[FilePart(staging,pos)]
    dhb=pack('I'*len(dh),*dh);fhb=pack('I'*len(fh),*fh)
    dhpos=0x50;dtpos=dhpos+len(dhb);fhpos=dtpos+len(dt);ftpos=fhpos+len(fhb)
    datap=align(ftpos+len(ft),0x10)
    header=pack('10Q',0x50,dhpos,len(dhb),dtpos,len(dt),fhpos,len(fhb),ftpos,len(ft),datap)
    return Blob(header,dhb,dt,fhb,ft,datap-ftpos-len(ft),*payload)

def integrity_hashes(blob,block,padded=False,workers=None,report=False):
    """Read sequentially and hash bounded batches in order."""
    workers=min(4,os.cpu_count() or 1) if workers is None else max(1,min(8,workers))
    result=bytearray();done=0;last=0.0
    def hash_batch(data):
        hashes=bytearray()
        with memoryview(data) as view:
            for off in range(0,len(data),block):
                with view[off:off+block] as part:
                    h=hashlib.sha256(part)
                    if padded and len(part)<block:h.update(bytes(block-len(part)))
                hashes.extend(h.digest())
        return hashes
    def accept(data,size):
        nonlocal done,last
        result.extend(data);done+=size;checkpoint()
        now=time.monotonic()
        if report and now-last>=0.15:progress(done,blob.size);last=now
    batch=max(1,(1024*1024)//block)*block
    if workers==1 or blob.size<8*1024*1024:
        for data in blob.chunks(batch):accept(hash_batch(data),len(data))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            pending=deque()
            for data in blob.chunks(batch):
                checkpoint();pending.append((pool.submit(hash_batch,data),len(data)))
                if len(pending)>=workers*2:
                    future,size=pending.popleft();accept(future.result(),size)
            while pending:
                future,size=pending.popleft();accept(future.result(),size)
    if report:progress(done,blob.size)
    return bytes(result)

def pfs_section(blob):
    block=0x10000
    while blob.size > block * block // 32: block *= 2
    hashes=integrity_hashes(blob,block)
    data_off=align(len(hashes),0x200)
    header=bytearray(0x200);struct.pack_into('<HBBB',header,0,2,1,2,1)
    header[8:40]=sha(hashes)
    struct.pack_into('<IIQQQQ',header,0x28,block,2,0,len(hashes),data_off,blob.size)
    return bytes(header),Blob(hashes,data_off-len(hashes),blob).pad(0x200)

def romfs_section(blob):
    block=0x4000
    levels=[blob]
    for layer in range(5):
        hashes=integrity_hashes(levels[0],block,padded=True,report=layer==0)
        levels.insert(0,Blob(hashes))
    master=sha(levels[0].read_head(block).ljust(block,b'\0'))
    header=bytearray(0x200);struct.pack_into('<HBBB',header,0,2,0,3,1)
    struct.pack_into('<4sIII',header,8,b'IVFC',0x20000,32,7)
    parts=[];off=0
    for i,level in enumerate(levels):
        struct.pack_into('<QQII',header,0x18+24*i,off,level.size,14,0)
        padded=level.pad(block);parts.append(padded);off+=padded.size
    header[0xc8:0xe8]=master
    return bytes(header),Blob(*parts)

def nca(sections, title_id, content_type, distribution=1):
    if len(sections)>4:raise ValueError('NCA supports at most four sections.')
    hdr=bytearray(0xc00);hdr[0x200:0x204]=b'NCA3'
    hdr[0x204:0x208]=bytes([distribution,content_type,1,0])
    struct.pack_into('<Q',hdr,0x210,title_id)
    struct.pack_into('<I',hdr,0x21c,0x000c1100)
    parts=[];off=0xc00
    for i,(fsh,body) in enumerate(sections):
        body=body.pad(0x200)
        if (off+body.size)//512>0xffffffff:
            raise ValueError('An NCA section exceeds the format limit (32-bit sector offsets, approximately 2 TiB per NCA).')
        struct.pack_into('<IIII',hdr,0x240+16*i,off//512,(off+body.size)//512,0,0)
        hdr[0x280+32*i:0x2a0+32*i]=sha(fsh)
        hdr[0x400+512*i:0x600+512*i]=fsh
        parts.append(body);off+=body.size
    struct.pack_into('<Q',hdr,0x208,off)
    return Blob(hdr,*parts)


def package(entries, kind='nsp'):
    """Stream NCA blobs into NSP/PFS0; no other output formats are emitted."""
    if kind != 'nsp':
        raise ValueError('NSP Box supports NSP output only.')
    result = filesystem(entries)
    if result.size > 0xffffffffffffffff:
        raise ValueError('NSP size exceeds the PFS0 64-bit size limit.')
    return result
