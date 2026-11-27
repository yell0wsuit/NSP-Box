"""Independent mmap reader for produced NSP files and embedded content."""
import hashlib,json,mmap,struct,sys,time
from pathlib import Path
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
import os

def checkpoint(): pass

def require(condition,message='Invalid container structure'):
    if not condition:raise AssertionError(message)


class Region:
    """Bounded mmap range without exported buffer views; always safe to close."""
    def __init__(self,mapping,offset=0,size=None):
        self.mapping=mapping;self.offset=offset;self.size=len(mapping)-offset if size is None else size
        if offset<0 or self.size<0 or offset+self.size>len(mapping):raise ValueError('Range is outside the container')
    def __len__(self):return self.size
    def __getitem__(self,key):
        if isinstance(key,slice):
            start,stop,step=key.indices(self.size)
            if step!=1:return bytes(self)[key]
            return Region(self.mapping,self.offset+start,max(0,stop-start))
        if key<0:key+=self.size
        if not 0<=key<self.size:raise IndexError(key)
        return self.mapping[self.offset+key]
    def __bytes__(self):return self.mapping[self.offset:self.offset+self.size]
    def read(self,offset,size):
        if not (0<=offset<=self.size and 0<=size<=self.size-offset):raise ValueError('Region read out of bounds')
        return self.mapping[self.offset+offset:self.offset+offset+size]

def u(fmt,buf,off=0):
    if isinstance(buf,Region):
        size=struct.calcsize('<'+fmt)
        if not (0<=off<=len(buf) and size<=len(buf)-off):raise ValueError('Structure exceeds region')
        return struct.unpack_from('<'+fmt,buf.mapping,buf.offset+off)
    return struct.unpack_from('<'+fmt,buf,off)

def digest(buf,check=None):
    check=checkpoint if check is None else check
    h=hashlib.sha256()
    if isinstance(buf,Region):
        # Views are scoped and explicitly released, including on cancellation.
        # No exported mmap buffers survive this function or an error traceback.
        with memoryview(buf.mapping) as mapped:
            for off in range(0,len(buf),4*1024*1024):
                check()
                with mapped[buf.offset+off:buf.offset+min(off+4*1024*1024,len(buf))] as block:
                    h.update(block)
    else:h.update(buf)
    return h.digest()

def block_digests(buf,block_size,padded=False,workers=None):
    workers=min(4,os.cpu_count() or 1) if workers is None else max(1,min(16,workers))
    # Batch adjacent blocks; bound outstanding work and join before mmap closes.
    if isinstance(buf,Region) and workers>1 and len(buf)>=8*1024*1024 and block_size>=2048:
        batch=max(1,(1024*1024)//block_size)*block_size
        def hash_batch(start):
            result=[]
            with memoryview(buf.mapping) as mapped:
                for off in range(start,min(start+batch,len(buf)),block_size):
                    count=min(block_size,len(buf)-off)
                    with mapped[buf.offset+off:buf.offset+off+count] as chunk:h=hashlib.sha256(chunk)
                    if padded and count<block_size:h.update(bytes(block_size-count))
                    result.append(h.digest())
            return result
        with ThreadPoolExecutor(max_workers=workers) as pool:
            starts=iter(range(0,len(buf),batch))
            while True:
                checkpoint()
                group=[]
                for _ in range(workers*2):
                    start=next(starts,None)
                    if start is None:break
                    group.append(pool.submit(hash_batch,start))
                if not group:break
                for future in group:
                    checkpoint()
                    yield from future.result()
        return
    if isinstance(buf,Region):
        with memoryview(buf.mapping) as mapped:
            for k,off in enumerate(range(0,len(buf),block_size)):
                if k%128==0:checkpoint()
                count=min(block_size,len(buf)-off)
                with mapped[buf.offset+off:buf.offset+off+count] as block:
                    h=hashlib.sha256(block)
                if padded and count<block_size:h.update(bytes(block_size-count))
                yield h.digest()
    else:
        for k,off in enumerate(range(0,len(buf),block_size)):
            if k%128==0:checkpoint()
            b=bytes(buf[off:off+block_size]);h=hashlib.sha256(b)
            if padded and len(b)<block_size:h.update(bytes(block_size-len(b)))
            yield h.digest()
def compare_files(originals,packed,expected_for,progress=lambda size:None,workers=None):
    """Hash bounded batches of mapped files; compare on the caller thread."""
    import threading
    from concurrent.futures import TimeoutError
    workers=min(4,os.cpu_count() or 1) if workers is None else max(1,min(16,workers))
    require(set(originals)==set(packed),'Packed file list differs from source')
    stop=threading.Event()
    def check_worker():
        if stop.is_set():raise InterruptedError('Verification cancelled.')
    def run(batch):
        return [(name,digest(packed[name],check_worker)) for name in batch]
    def batches():
        batch=[];size=0
        for name in originals:
            checkpoint();n=len(packed[name])
            if batch and (size+n>4*1024*1024 or len(batch)>=256):
                yield batch;batch=[];size=0
            batch.append(name);size+=n
        if batch:yield batch
    def accept(results):
        for name,actual in results:
            checkpoint()
            expected=expected_for(originals[name])
            require(expected is not None and actual==expected,'Packed file differs: '+name)
            progress(len(packed[name]))
            yield name,expected
    if workers==1 or len(originals)<2 or sum(map(len,packed.values()))<8*1024*1024:
        for name in originals:
            checkpoint()
            yield from accept([(name,digest(packed[name]))])
        return
    with ThreadPoolExecutor(max_workers=workers) as pool:
        try:
            pending=iter(batches())
            while True:
                group=[]
                for _ in range(workers*2):
                    batch=next(pending,None)
                    if batch is None:break
                    group.append(pool.submit(run,batch))
                if not group:break
                for future in group:
                    while True:
                        checkpoint()
                        try:results=future.result(timeout=0.1);break
                        except TimeoutError:continue
                    yield from accept(results)
        finally:
            stop.set()

def file_digest(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        while b:=f.read(4*1024*1024):
            checkpoint();h.update(b)
    return h.digest()

def partition(buf,offset=0):
    magic,n,stsize,_=u('4sIII',buf,offset);require(magic in (b'PFS0',b'HFS0'))
    es=0x40 if magic==b'HFS0' else 0x18;strings=offset+16+n*es;data=strings+stsize
    if data>len(buf):raise ValueError('Partition table out of bounds')
    result={}
    for i in range(n):
        checkpoint()
        at=offset+16+i*es;rel,size,nameoff=u('QQI',buf,at)
        if nameoff>=stsize:raise ValueError('Partition name offset out of bounds')
        start=strings+nameoff
        if isinstance(buf,Region):
            end=buf.mapping.find(b'\0',buf.offset+start,buf.offset+data)
            if end<0:raise ValueError('Unterminated partition name')
            name=buf.mapping[buf.offset+start:end].decode()
        else:
            end=start
            while end<data and buf[end]!=0:end+=1
            if end==data:raise ValueError('Unterminated partition name')
            name=bytes(buf[start:end]).decode()
        if not name or name in result:raise ValueError('Empty or duplicate partition name')
        if rel>len(buf)-data or size>len(buf)-data-rel:raise ValueError('Partition payload out of bounds')
        view=buf[data+rel:data+rel+size];require(len(view)==size)
        if magic==b'HFS0':
            hn,ho=u('IQ',buf,at+20)
            if ho>size or hn>size-ho:raise ValueError('HFS hash range out of bounds')
            require(digest(view[ho:ho+hn])==bytes(buf[at+32:at+64]),('HFS hash',name))
        result[name]=view
    return result

def nca_sections(buf,verify_payload=True,plans=None):
    require(len(buf)>=0xc00 and bytes(buf[0x200:0x204])==b'NCA3')
    require(u('Q',buf,0x208)[0]==len(buf))
    title=u('Q',buf,0x210)[0];sections=[]
    for i in range(4):
        start,end=u('II',buf,0x240+16*i)
        if not start and not end:continue
        if not (6<=start<end and end*512<=len(buf)):raise ValueError('NCA section out of bounds')
        header=buf[0x400+512*i:0x600+512*i]
        require(digest(header)==bytes(buf[0x280+32*i:0x2a0+32*i]))
        require(header[4]==1,'Expected plaintext section')
        body=buf[start*512:end*512];require(len(body)==(end-start)*512)
        if header[3]==2:
            block,count=u('II',header,0x28);require(count==2)
            ho,hs,do,ds=u('4Q',header,0x30)
            hashes=body[ho:ho+hs];data=body[do:do+ds]
            require(0<block<=16*1024*1024 and len(hashes)==hs and len(data)==ds,'PFS section bounds')
            if verify_payload:
                require(digest(hashes)==bytes(header[8:40]),'PFS master hash')
                require(((ds+block-1)//block)*32<=len(hashes),'PFS hash table too short')
                if plans is not None:plans.append((data,block,False,hashes,'PFS block hash'))
                else:
                    with closing(block_digests(data,block)) as generated:
                        for k,actual in enumerate(generated):
                            require(actual==bytes(hashes[k*32:k*32+32]),'PFS block hash')
            sections.append(('pfs',data))
        elif header[3]==3:
            require(bytes(header[8:12])==b'IVFC')
            count=u('I',header,0x14)[0]-1;require(count==6)
            expected=header[0xc8:0xe8]
            for j in range(count):
                off,size,order=u('QQI',header,0x18+j*24)
                if order>24:raise ValueError('Unsupported IVFC block size')
                block=1<<order
                data=body[off:off+size];require(len(data)==size)
                if verify_payload:
                    require(((size+block-1)//block)*32<=len(expected),'IVFC hash table too short')
                    if plans is not None:plans.append((data,block,True,expected,('IVFC',j)))
                    else:
                        with closing(block_digests(data,block,padded=True)) as generated:
                            for k,actual in enumerate(generated):
                                require(actual==bytes(expected[k*32:k*32+32]),('IVFC',j,k))
                expected=data
            sections.append(('romfs',data))
        else:raise ValueError('Unsupported hash')
    return title,buf[0x205],sections

def verified_nca(buf,workers=None):
    """Hash the NCA in physical order while checking adjacent integrity blocks.

    Every byte still contributes to the full SHA-256, including gaps and padding.
    Block hashes remain independent; only their memory traversal is interleaved.
    """
    workers=min(4,os.cpu_count() or 1) if workers is None else max(1,min(16,workers))
    if not isinstance(buf,Region) or len(buf)<8*1024*1024:
        return digest(buf),nca_sections(buf)
    plans=[]
    parsed=nca_sections(buf,plans=plans)
    plans.sort(key=lambda plan:plan[0].offset)
    cursor=buf.offset
    for data,block,padded,expected,label in plans:
        if not len(data):continue
        if data.offset<cursor or data.offset+len(data)>buf.offset+len(buf):
            # Preserve the original verifier's semantics for unusual overlapping layouts.
            return digest(buf),nca_sections(buf)
        cursor=data.offset+len(data)
    h=hashlib.sha256()
    from collections import deque
    def validate(data,block,padded,expected,label,start,end):
        with memoryview(data.mapping) as mapped:
            for off in range(start,end,block):
                count=min(block,len(data)-off)
                with mapped[data.offset+off:data.offset+off+count] as chunk:
                    bh=hashlib.sha256(chunk)
                if padded and count<block:bh.update(bytes(block-count))
                k=off//block
                require(bh.digest()==bytes(expected[k*32:k*32+32]),label)
    cursor=buf.offset
    with memoryview(buf.mapping) as mapped,ThreadPoolExecutor(max_workers=workers) as pool:
        pending=deque()
        def consume():
            checkpoint();pending.popleft().result()
        def hash_range(start,end):
            for off in range(start,end,4*1024*1024):
                checkpoint()
                with mapped[off:min(end,off+4*1024*1024)] as chunk:h.update(chunk)
        for data,block,padded,expected,label in plans:
            if not len(data):continue
            hash_range(cursor,data.offset)
            batch=max(1,(4*1024*1024)//block)*block
            for off in range(0,len(data),batch):
                checkpoint()
                end=min(off+batch,len(data))
                if workers==1 or end-off<64*1024:
                    validate(data,block,padded,expected,label,off,end)
                else:
                    pending.append(pool.submit(validate,data,block,padded,expected,label,off,end))
                hash_range(data.offset+off,data.offset+end)
                if len(pending)>=workers*2:consume()
            cursor=data.offset+len(data)
        hash_range(cursor,buf.offset+len(buf))
        while pending:consume()
    return h.digest(),parsed

def romfs_files(buf,validate_name=None):
    """Bounded RomFS traversal: never follow repeated offsets in imported NSPs."""
    if validate_name is None:
        def validate_name(name):
            require(name not in ('','.','..') and not any(c in name for c in '/\\\0'),'Invalid RomFS filename')
    vals=u('10Q',buf);require(vals[0]==0x50,'Invalid RomFS header.')
    dt,ds,ft,fs,data=vals[3],vals[4],vals[7],vals[8],vals[9]
    require(0x50<=dt<=len(buf) and ds<=len(buf)-dt and ft<=len(buf) and fs<=len(buf)-ft and data<=len(buf),'Invalid RomFS table bounds.')
    result={};seen_dirs=set();seen_files=set()
    def visit(off,prefix,depth=0):
        require(depth<256,'RomFS directory nesting is too deep.')
        while off!=0xffffffff:
            check_cancel=checkpoint;check_cancel()
            require(off not in seen_dirs and off+24<=ds,'Cyclic or invalid RomFS directory.');seen_dirs.add(off)
            par,sibling,child,first,hl,n=u('6I',buf,dt+off)
            require(n<=ds-off-24,'RomFS directory name out of bounds.')
            name=bytes(buf[dt+off+24:dt+off+24+n]).decode('utf-8')
            if name:validate_name(name)
            current=prefix+'/'+name if prefix and name else prefix or name
            entry=first
            while entry!=0xffffffff:
                check_cancel();require(entry not in seen_files and entry+32<=fs,'Cyclic or invalid RomFS file.');seen_files.add(entry)
                fp,nextfile,fo,size,fh,fn=u('IIQQII',buf,ft+entry)
                require(fn<=fs-entry-32 and fo<=len(buf)-data and size<=len(buf)-data-fo,'RomFS file out of bounds.')
                name=bytes(buf[ft+entry+32:ft+entry+32+fn]).decode('utf-8');validate_name(name)
                path=current+'/'+name if current else name;require(path not in result,'Duplicate RomFS file.')
                result[path]=buf[data+fo:data+fo+size];entry=nextfile
            if child!=0xffffffff:visit(child,current,depth+1)
            off=sibling
    visit(0,'');return result

