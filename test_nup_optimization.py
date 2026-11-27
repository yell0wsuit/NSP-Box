"""Read/compression-count regressions, decoder windows and 64-bit format sizes."""
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace
import hashlib,io,struct,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).parent/'src'))
import nup_format as nf,nup_tools as nt,container_format as fmt,engine
from test_nup import snapshot,TID

class NupOptimizationTests(unittest.TestCase):
    def setUp(self):
        scratch=Path(__file__).parent/'test-work';scratch.mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(dir=scratch);self.root=Path(self.tmp.name)
    def tearDown(self):self.tmp.cleanup()
    def test_decoder_accepts_writer_frames_above_old_1mib_cap(self):
        data=b'abcde'*2000000;path=self.root/'window.nup'
        nf.pack([nf.Package(TID,0,0,{'romfs/data':nf.Source.data(data)})],path)
        with nf.Archive(path) as a:
            f=a.files[0];params=nf.zstd.get_frame_parameters(a.read_at(f[2],18));self.assertGreater(params.window_size,1<<20)
            a.verify();self.assertEqual(a.packages[0].files['romfs/data'].read_small(),data)
        nf.extract(path,self.root/'extracted');self.assertEqual((self.root/'extracted/base/romfs/data').read_bytes(),data)
    def test_duplicate_not_compressed_or_verified_twice_and_false_prefix_not_shared(self):
        first=b'a'*(1024*1024);different=first[:65536]+b'b'*(len(first)-65536)
        files={'romfs/a':nf.Source.data(first),'romfs/b':nf.Source.data(first),'romfs/c':nf.Source.data(different)}
        compressor=nf.zstd.ZstdCompressor;calls=[]
        class CountingCompressor:
            def __init__(self,*a,**kw):self.inner=compressor(*a,**kw)
            def compress(self,data):calls.append(len(data));return self.inner.compress(data)
            def compressobj(self,*a,**kw):calls.append(kw.get('size'));return self.inner.compressobj(*a,**kw)
        def factory(*a,**kw):return CountingCompressor(*a,**kw)
        path=self.root/'duplicates.nup'
        with patch.object(nf.zstd,'ZstdCompressor',factory):result=nf.pack([nf.Package(TID,0,0,files)],path)
        self.assertEqual(len(calls),2);self.assertEqual(result['duplicate_files_skipped'],1)
        with nf.Archive(path) as a:
            called=[];original=nf.Slice
            def extent(*args,**kwargs):called.append(args[1]);return original(*args,**kwargs)
            with patch.object(nf,'Slice',extent):a.verify()
            self.assertEqual(len(called),2)
            self.assertEqual(called,sorted(called))
            self.assertEqual(a.packages[0].files['romfs/c'].read_small(),different)
    def test_verify_raw_and_empty_extents_with_progress(self):
        data=hashlib.shake_256(b'raw fixture').digest(2*nf.BLOCK+17)
        path=self.root/'raw.nup'
        files={'romfs/raw':nf.Source.data(data),'romfs/empty':nf.Source.data(b'')}
        nf.pack([nf.Package(TID,0,0,files)],path)
        with nf.Archive(path) as a:
            raw=next(f for f in a.files if f[0]=='raw')
            self.assertEqual(raw[5],0)
            progress=[]
            with patch.object(nf,'Slice',side_effect=AssertionError('Raw extent reopened')):
                self.assertTrue(a.verify(lambda stage,value:progress.append(value))['verified'])
            self.assertEqual(progress[-1],100)
            self.assertEqual(progress,sorted(progress))
            offset=raw[2]
        with path.open('r+b') as f:
            f.seek(offset);f.write(bytes([data[0]^1]))
        with nf.Archive(path) as a:
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):a.verify()
    def test_parallel_verify_matches_serial_and_detects_corruption(self):
        data=hashlib.shake_256(b'parallel raw').digest(4*nf.BLOCK+17)
        path=self.root/'parallel.nup'
        files={'romfs/raw':nf.Source.data(data),'romfs/compressed':nf.Source.data(b'abc'*2000000),
               'romfs/duplicate':nf.Source.data(data),'romfs/empty':nf.Source.data(b'')}
        nf.pack([nf.Package(TID,0,0,files)],path,verify=False)
        with nf.Archive(path) as a:
            self.assertEqual(a.verify(workers=1),a.verify(workers=4))
            offset=next(f[2] for f in a.files if f[0]=='raw')
        with path.open('r+b') as f:
            f.seek(offset);f.write(bytes([data[0]^1]))
        with nf.Archive(path) as a:
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'):a.verify(workers=4)
    def test_parallel_pack_extract_equivalence(self):
        raw=hashlib.shake_256(b'fixture').digest(2*nf.BLOCK+7)
        files={'romfs/a':nf.Source.data(raw),'romfs/b':nf.Source.data(raw),
               'romfs/c':nf.Source.data(b'abc'*500000),'romfs/d':nf.Source.data(b'')}
        for workers in (1,4):
            path=self.root/f'pack-{workers}.nup'
            result=nf.pack([nf.Package(TID,0,0,files)],path,workers=workers)
            self.assertEqual(result['duplicate_files_skipped'],1)
            with nf.Archive(path) as a:
                self.assertTrue(a.verify()['verified'])
                self.assertEqual(a.packages[0].files['romfs/a'].read_small(),raw)
            dest=self.root/f'extracted-{workers}';nf.extract(path,dest,workers=workers)
            for name,source in files.items():
                self.assertEqual((dest/'base'/name).read_bytes(),source.read_small())
    def test_large_native_compression_round_trip(self):
        data=b'large native frame'*(2*1024*1024)
        path=self.root/'native.nup'
        nf.pack([nf.Package(TID,0,0,{'romfs/data':nf.Source.data(data)})],path,workers=2,large_raw=False)
        with nf.Archive(path) as a:
            self.assertEqual(a.files[0][5],1)
            self.assertTrue(a.verify()['verified'])
            self.assertEqual(b''.join(a.file_chunks(0)),data)
    def test_contiguous_romfs_high_file_count(self):
        # CI exercises 100k virtual files; set NSP_BOX_STRESS_FILES=400000 locally.
        import os,time
        count=int(os.environ.get('NSP_BOX_STRESS_FILES','100000'))
        npdm=bytearray(256);npdm[:4]=b'META';struct.pack_into('<II',npdm,0x70,0x80,0x80)
        npdm[0x80:0x84]=b'ACI0';struct.pack_into('<Q',npdm,0x90,TID)
        files={'exefs/main.npdm':nf.Source.data(bytes(npdm)),'exefs/main':nf.Source.data(b'NSO0'+bytes(256))}
        files.update((f'romfs/group{i//1000:04d}/file{i:07d}.bin',nf.Source.data(struct.pack('<Q',i)+b'payload')) for i in range(count))
        archive=self.root/'stress.nup';output=self.root/'stress.nsp'
        start=time.perf_counter();nf.pack([nf.Package(TID,0,0,files)],archive)
        packed=time.perf_counter()
        original_open=Path.open
        def guarded(path,*args,**kwargs):
            if any(part.startswith('.nup-nsp-') for part in path.parts) and 'romfs' in path.parts:
                raise AssertionError('Physical RomFS file opened during contiguous conversion')
            return original_open(path,*args,**kwargs)
        with patch.object(Path,'open',guarded):nt.nup_to_nsp(archive,output)
        converted=time.perf_counter()
        with nt.nsp_packages(output,deep=False) as packages:
            actual=packages[0].files
            self.assertEqual(sum(name.startswith('romfs/') for name in actual),count)
            for i in (0,count//2,count-1):
                self.assertEqual(actual[f'romfs/group{i//1000:04d}/file{i:07d}.bin'].read_small(),struct.pack('<Q',i)+b'payload')
        print(f'High-file-count stress: {count} files; pack {packed-start:.2f}s; convert {converted-packed:.2f}s',flush=True)
    def test_contiguous_matches_legacy(self):
        game=snapshot(self.root/'Game',{'z':b'z','a/one':b'a','a/two':b'','日本語/x':b'xyz'})
        archive=self.root/'fixture.nup';nt.pack_folder(game,archive)
        a=self.root/'old.nsp';b=self.root/'new.nsp'
        nt.nup_to_nsp(archive,a,contiguous=False);nt.nup_to_nsp(archive,b)
        self.assertEqual(a.read_bytes(),b.read_bytes())
    def test_small_snapshot_keeps_base_only_and_discards_old_replacements(self):
        root=self.root/'Bundle';snapshot(root/'base',{'same':b'old','needed':b'keep'})
        snapshot(root/'updates/65536',{'same':b'older update','obsolete':b'old update only'},1)
        snapshot(root/'updates/131072',{'same':b'latest','new':b'latest only'},2)
        npdm=root/'updates/131072/exefs/main.npdm';data=bytearray(npdm.read_bytes());data[0x50]=1;npdm.write_bytes(data)
        output=self.root/'small.nup';result=nt.pack_folder(root,output)
        with nf.Archive(output) as a:
            self.assertEqual(len(a.packages),1);p=a.packages[0];self.assertEqual(p.kind,0);self.assertEqual(p.version,131072)
            self.assertEqual(p.files['romfs/same'].read_small(),b'latest');self.assertEqual(p.files['romfs/needed'].read_small(),b'keep')
            self.assertNotIn('romfs/obsolete',p.files);self.assertEqual(p.files['exefs/main'].read_small(),(root/'updates/131072/exefs/main').read_bytes())
            self.assertEqual(dict(p.metadata)[1],npdm.read_bytes());self.assertEqual(dict(p.metadata)[7],bytes([2])*32)
        self.assertGreater(result['omitted_version_bytes'],0)
        nt.pack_folder(root,self.root/'archive.nup',latest_snapshot=False)
        with nf.Archive(self.root/'archive.nup') as a:self.assertEqual(len(a.packages),3)
    def test_nsp_inspection_avoids_payload_hashing_but_conversion_checks_it(self):
        game=snapshot(self.root/'Game',{'payload':b'12345'*400000});s=engine.find_snapshots(game)[0][0]
        path=self.root/'game.nsp';engine.build(s,path,'Example','1')
        original=nt.vf.digest;hashed=[]
        def spy(buf):hashed.append(len(buf));return original(buf)
        with patch.object(nt.vf,'digest',spy):
            with nt.nsp_packages(path,deep=False) as p:self.assertEqual(p[0].title_id,TID)
        self.assertLess(max(hashed),1<<20)
        hashed.clear()
        with patch.object(nt.vf,'digest',spy):nt.nsp_to_nup(path,self.root/'game.nup')
        self.assertGreater(max(hashed),1<<20)
        with path.open('r+b') as f:f.seek(-1,2);last=f.read(1);f.seek(-1,2);f.write(bytes([last[0]^1]))
        with self.assertRaises(ValueError):nt.nsp_to_nup(path,self.root/'corrupt.nup')
        self.assertFalse((self.root/'corrupt.nup').exists())
    def test_folder_inspection_reused_and_directory_changes_refused(self):
        game=snapshot(self.root/'Game',{'data':b'original'});prepared=nt.prepare_folder(game)
        with patch.object(nt,'discover',side_effect=AssertionError('Repeated folder discovery')):
            nt.pack_folder(game,self.root/'cached.nup',prepared=prepared)
        (game/'romfs/new').write_bytes(b'new file')
        with self.assertRaisesRegex(ValueError,'folder changed'):nt.pack_folder(game,self.root/'stale.nup',prepared=prepared)
        self.assertFalse((self.root/'stale.nup').exists())
    def test_changed_cached_file_refused_and_partial_removed(self):
        game=snapshot(self.root/'Game',{'data':b'original'});prepared=nt.prepare_folder(game)
        (game/'romfs/data').write_bytes(b'modified')
        with self.assertRaisesRegex(ValueError,'changed'):nt.pack_folder(game,self.root/'stale.nup',prepared=prepared)
        self.assertFalse((self.root/'stale.nup').exists());self.assertFalse(list(self.root.glob('*.partial')))
    def test_nsp_headers_support_40_and_96_gib_without_allocating_payloads(self):
        for size in (40<<30,96<<30):
            nca=fmt.nca([(bytes(512),fmt.Blob(size))],TID,0,0)
            hdr=nca.read_head(0xc00);start,end=struct.unpack_from('<II',hdr,0x240)
            self.assertGreater(end*512,32<<30);self.assertEqual(end*512,nca.size)
            package=fmt.package([('large.nca',nca)]);head=package.read_head(128)
            self.assertEqual(struct.unpack_from('<Q',head,24)[0],nca.size);self.assertGreater(package.size,size)
        with self.assertRaisesRegex(ValueError,'2 TiB'):fmt.nca([(bytes(512),fmt.Blob(2<<40))],TID,0,0)
    def test_nup_reader_uses_64_bit_offsets_and_lengths(self):
        # A virtual archive exercises the real parser at 40 GiB without a huge file.
        path=self.root/'virtual.nup';path.write_bytes(b'fixture')
        size=40<<30;pool=b'romfshuge.bin';po=48+64+2*24+80+2*4;ts=nf.align(po+len(pool));bo=nf.align(128+ts);fs=bo+size
        toc=bytearray(ts);nf.TOC.pack_into(toc,0,b'TOC\1',1,2,1,po,len(pool),0)
        nf.PKG.pack_into(toc,48,TID,0,nf.NONE,1,0,0,0,0,0,0,0,bytes(20))
        nf.DIR.pack_into(toc,112,0,0,0,1,0);nf.DIR.pack_into(toc,136,0,5,1,1,0)
        nf.FILE.pack_into(toc,160,5,8,size,bo,size,bytes(32),0,0,0,bytes(12))
        struct.pack_into('<II',toc,240,1,2);toc[po:po+len(pool)]=pool
        identity=hashlib.sha256(struct.pack('<QIB',TID,0,0)).digest()[:16]
        header=nf.SUPER.pack(b'NUP\1',128,1,128,ts,hashlib.sha256(toc).digest(),bo,fs,1,0,identity,bytes(32))
        def read_at(a,off,n):
            if off==0 and n==128:return header
            if off==128 and n==ts:return toc
            raise AssertionError('Unexpected payload read during structural inspection')
        with patch.object(Path,'stat',return_value=SimpleNamespace(st_size=fs,st_mtime_ns=0)),patch.object(nf.Archive,'read_at',read_at):
            with nf.Archive(path) as a:self.assertEqual(a.files[0][1],size);self.assertEqual(a.stats['archive_size'],fs)

if __name__=='__main__':unittest.main()
