import unittest
import requests_mock
import json
from subdomain_scanner import SubdomainScanner  # Replace with actual module name

class TestSubdomainScanner(unittest.TestCase):
    def test_invalid_domain(self):
        """Test that an invalid domain raises a ValueError."""
        with self.assertRaises(ValueError):
            SubdomainScanner("invalid_domain")

    @requests_mock.Mocker()
    def test_subdomain_check(self, mock):
        """Test subdomain scanning with mocked HTTP responses."""
        # Mock responses for subdomains
        mock.get("https://www.example.com", text="<html><title>Test Title</title></html>", status_code=200)
        mock.get("https://mail.example.com", status_code=404)
        
        scanner = SubdomainScanner("example.com", subdomains_list=["www", "mail"])
        results = scanner.run()
        
        self.assertEqual(len(results['subdomains_found']), 1)
        self.assertEqual(results['subdomains_found'][0]['url'], "https://www.example.com")
        self.assertEqual(results['subdomains_found'][0]['title'], "Test Title")

    def test_output_file(self):
        """Test saving results to a JSON file."""
        scanner = SubdomainScanner("example.com", subdomains_list=["www"])
        scanner.set_output_file("test_results.json")
        # Simulate scan results
        scanner.subdomains_found = [{'url': 'https://www.example.com', 'status_code': 200, 'server': 'Apache', 'title': 'Test'}]
        scanner.save_results({'subdomains_found': scanner.subdomains_found})
        
        with open("test_results.json", 'r') as f:
            data = json.load(f)
            self.assertIn('subdomains_found', data)
            self.assertEqual(len(data['subdomains_found']), 1)
            self.assertEqual(data['subdomains_found'][0]['url'], "https://www.example.com")

if __name__ == '__main__':
    unittest.main()
