"""Ensure performance improvements retain corruption and mutation detection."""
from pathlib import Path
from unittest.mock import patch
import mmap,struct,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).parent/'src'))
import engine,container_format as fmt,verify_format as verifier

class VerificationSafetyTests(unittest.TestCase):
    def setUp(self):
        scratch=Path(__file__).parent/'test-work';scratch.mkdir(exist_ok=True)
        self.tmp=tempfile.TemporaryDirectory(prefix='safety-',dir=scratch);self.root=Path(self.tmp.name)
        self.game=self.root/'Example Game';(self.game/'exefs').mkdir(parents=True);(self.game/'romfs').mkdir()
        b=bytearray(0x100);b[:4]=b'META';struct.pack_into('<II',b,0x70,0x80,0x80);b[0x80:0x84]=b'ACI0'
        struct.pack_into('<Q',b,0x90,0x0400111122220000)
        (self.game/'exefs/main.npdm').write_bytes(b);(self.game/'exefs/main').write_bytes(b'NSO0'+bytes(128))
        (self.game/'romfs/data.bin').write_bytes(b'original'*20000);(self.game/'romfs/empty.bin').write_bytes(b'')
        self.snapshot=engine.find_snapshots(self.game)[0][0];self.out=self.root/'Output.nsp'
    def tearDown(self):self.tmp.cleanup()
    def test_readback_does_not_reread_source_files(self):
        original_verify=engine.verify_image;original_open=Path.open
        def verify_without_source_reads(path,snapshot,inventory,notify,cancel,source_hashes=None):
            self.assertEqual(set(source_hashes),set(inventory));self.assertTrue(all(len(v)==32 for v in source_hashes.values()))
            def guarded(p,*args,**kw):
                if p in inventory:raise AssertionError('Redundant source reread')
                return original_open(p,*args,**kw)
            with patch.object(Path,'open',guarded):
                return original_verify(path,snapshot,inventory,notify,cancel,source_hashes)
        with patch.object(engine,'verify_image',verify_without_source_reads):
            report=engine.build(self.snapshot,self.out,'Example','1')
        self.assertTrue(report['verified']);self.assertEqual(report['source_file_count'],4)
    def test_output_corruption_still_detected(self):
        def notify(stage,value):
            if stage=='Verifying container integrity':
                partial=next(self.root.glob('*.partial'))
                with partial.open('r+b') as f:
                    f.seek(-1,2);b=f.read(1);f.seek(-1,2);f.write(bytes([b[0]^1]))
        with self.assertRaises(AssertionError):engine.build(self.snapshot,self.out,'Example','1',notify=notify)
        self.assertFalse(self.out.exists());self.assertFalse(list(self.root.glob('*.partial')))
    def test_input_mutation_still_detected(self):
        def notify(stage,value):
            if stage=='Verifying container integrity':(self.game/'romfs/data.bin').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'changed'):engine.build(self.snapshot,self.out,'Example','1',notify=notify)
        self.assertFalse(self.out.exists())
    def test_parallel_block_hashes_match_serial(self):
        path=self.root/'blocks.bin';path.write_bytes(b'abcdefgh'*(1024*1024)+b'tail')
        with path.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
            region=verifier.Region(mm)
            for padded in (False,True):
                self.assertEqual(list(verifier.block_digests(region,4096,padded,workers=1)),
                                 list(verifier.block_digests(region,4096,padded,workers=4)))
    def test_parallel_file_comparison_and_corruption(self):
        path=self.root/'mapped.bin';data=b'a'*(5*1024*1024)+b'b'*(5*1024*1024)
        path.write_bytes(data)
        import hashlib
        from contextlib import closing
        expected={'a':hashlib.sha256(data[:len(data)//2]).digest(),'b':hashlib.sha256(data[len(data)//2:]).digest()}
        with path.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
            region=verifier.Region(mm);packed={'a':region[:len(data)//2],'b':region[len(data)//2:]}
            for workers in (1,4):
                self.assertEqual(dict(verifier.compare_files(dict(a='a',b='b'),packed,expected.get,workers=workers)),expected)
            with closing(verifier.compare_files(dict(a='a',b='b'),packed,lambda _:bytes(32),workers=4)) as results:
                with self.assertRaises(AssertionError):list(results)
    def test_fused_nca_hash_and_integrity(self):
        import hashlib
        fmt.configure()
        header,section=fmt.romfs_section(fmt.Blob(b'abcdefgh'*(1200000)))
        blob=fmt.nca([(header,section)],self.snapshot.title_id,0)
        path=self.root/'fused.nca'
        with path.open('wb') as f:
            for chunk in blob.chunks():f.write(chunk)
        with path.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
            region=verifier.Region(mm);expected=verifier.digest(region)
            for workers in (1,4):
                actual,parsed=verifier.verified_nca(region,workers=workers)
                self.assertEqual(actual,expected)
                self.assertEqual(parsed[:2],verifier.nca_sections(region)[:2])
        start=0xc00+struct.unpack_from('<Q',header,0x18+5*24)[0]
        with path.open('r+b') as f:f.seek(start);f.write(b'X')
        with path.open('rb') as f,mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
            with self.assertRaises(AssertionError):verifier.verified_nca(verifier.Region(mm),workers=4)
    def test_failed_block_hash_releases_mmap(self):
        fmt.configure();header,section=fmt.romfs_section(fmt.Blob(b'a'*50000))
        blob=fmt.nca([(header,section)],self.snapshot.title_id,0)
        payload=b''.join(blob.chunks());path=self.root/'Invalid.nca';path.write_bytes(payload)
        start=0xc00+struct.unpack_from('<Q',header,0x18+5*24)[0]
        with path.open('r+b') as f:f.seek(start);f.write(b'b')
        with path.open('rb') as f:
            with mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) as mm:
                with self.assertRaises(AssertionError):verifier.nca_sections(verifier.Region(mm))
        path.unlink()  # Also prove no mapping/file handle remains open on Windows.

if __name__=='__main__':unittest.main(verbosity=2)
