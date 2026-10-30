import unittest
from test_hardening import m

class PufferCaseTests(unittest.TestCase):
    def test_existing_documents_path(self):
        self.assertEqual(m.pubg_target('Documents/ShadowTrackerExtra/Saved/Paks/Puffer_Temp/game.pak'), 'Documents/ShadowTrackerExtra/Saved/Paks/puffer_temp/game.pak')
    def test_nested_shadowtracker_path(self):
        self.assertEqual(m.pubg_target('wrapper/ShadowTrackerExtra/Saved/Paks/PuFfEr_TeMp/game.pak'), 'Documents/ShadowTrackerExtra/Saved/Paks/puffer_temp/game.pak')
    def test_selected_folder(self):
        self.assertEqual(m.pubg_target('game.pak', 'puffer_temp'), 'Documents/ShadowTrackerExtra/Saved/Paks/puffer_temp/game.pak')
    def test_preview_build(self):
        entries=[('Documents/ShadowTrackerExtra/Saved/Paks/Puffer_Temp/game.pak', b'abc')]
        bundles=[m.BUNDLE_PUBG_GLOBAL]
        p=m.preview_paths(entries,'pubg-global',bundles,False,2)
        r=m.build_rules_from_entries(entries,'pubg-global',bundles,False,2)
        self.assertEqual(p['rows'][0]['target'],r[0]['relativePath'])
        self.assertIn('/puffer_temp/',r[0]['relativePath'])
