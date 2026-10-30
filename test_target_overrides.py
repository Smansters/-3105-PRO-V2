import importlib.util
from pathlib import Path
import unittest
spec = importlib.util.spec_from_file_location('core_target_test', Path(__file__).resolve().parents[1] / '3105tool.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
class TargetOverrideTests(unittest.TestCase):
    def test_preview_matches_build(self):
        entries=[('Resources/1.64.1/hero.bytes',b'hero')]
        overrides={'Resources/1.64.1/hero.bytes': {'com.garena.game.kgvn':'Documents/Custom/hero.bytes'}}
        p=mod.preview_paths(entries,'lq',['com.garena.game.kgvn'],False,9,target_overrides=overrides)
        r=mod.build_rules_from_entries(entries,'lq',['com.garena.game.kgvn'],False,9,target_overrides=overrides)
        self.assertEqual(p['rows'][0]['target'],r[0]['relativePath'])
        self.assertIn('terminal',p['rows'][0])
    def test_reject_traversal(self):
        for path in ('Documents/../private','/Documents/a','C:/x','Documents//x'):
            with self.assertRaises(ValueError):mod.validate_target_path(path)
    def test_reject_duplicate_override(self):
        e=[('Resources/1.64.1/a.bytes',b'a'),('Resources/1.64.1/b.bytes',b'b')]
        with self.assertRaises(ValueError):mod.build_rules_from_entries(e,'lq',['com.garena.game.kgvn'],False,9,target_overrides={k:'Documents/same.bytes' for k,_ in e})
