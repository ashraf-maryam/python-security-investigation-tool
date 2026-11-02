import unittest
from src.triage import analyze

class TestTriage(unittest.TestCase):
    def test_empty(self): self.assertEqual(analyze([]),[])
    def test_normal_login_no_alert(self):
        self.assertEqual(analyze([dict(id='1',host='x',src_ip='a',event_type='ssh_success')]),[])
    def test_failed_login_threshold(self):
        data=[dict(id=str(i),host='x',src_ip='a',event_type='ssh_failed') for i in range(3)]
        self.assertEqual(analyze(data)[0]['rule'],'AUTH-001')
    def test_failed_success(self):
        data=[dict(id=str(i),host='x',src_ip='a',event_type='ssh_failed') for i in range(3)]
        data.append(dict(id='4',host='x',src_ip='a',event_type='ssh_success'))
        self.assertEqual(analyze(data)[0]['rule'],'AUTH-002')
    def test_endpoint(self):
        self.assertEqual(analyze([dict(id='1',host='x',src_ip='none',event_type='malware_detected')])[0]['severity'],'HIGH')
    def test_privilege(self):
        self.assertEqual(analyze([dict(id='1',host='x',src_ip='none',event_type='privilege_change')])[0]['rule'],'IAM-001')
    def test_has_evidence(self):
        self.assertTrue(analyze([dict(id='1',host='x',src_ip='none',event_type='privilege_change')])[0]['event_ids'])
    def test_distinct_ips(self):
        data=[dict(id=str(i),host='x',src_ip='a',event_type='ssh_failed') for i in range(3)]
        data.append(dict(id='4',host='x',src_ip='b',event_type='ssh_success'))
        self.assertEqual(analyze(data)[0]['rule'],'AUTH-001')
if __name__=="__main__":unittest.main()
