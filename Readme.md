
# Overview
1. Do EDA on Top 25 CWEs file from MITRE
2. Add CVE Descriptions to Top 25
3. Remove Notes

## Do EDA on Top 25 CWEs file from MITRE

1. top25_eda.ipynb


## Add CVE Descriptions to Top 25 and remove Rationale, and CWE entries that are not a CWE

1. nvd/CVSSData.ipynb gets the CVE Descriptions from NVD JSON files
2. top25_add_cve_desc.ipynb adds CVE Descriptions to Top 25 entries
   1. output: ./data_out/top25-mitre-mapping-analysis-2023-public_with_cve_descriptions.csv
3. Remove entries where CWE is not a CWE e.g. NVD-CWE-Insufficient-Info, UNSURE, CWE-RESEARCH...
   1. this reduces the number of entries from 9712 to 8522


## CWE JSON

1. download CWE JSON
   1. wget https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/json_repo/cwe.json  
2. cwe_json.ipynb
   1. input: 
      1. ./data_in/cwe.json  
      2. ./data_out/top25-mitre-mapping-analysis-2023-public_with_cve_descriptions.csv
   2. steps
      1. remove 'ContentHistory', 'Views', 'Categories', 'References', 'TaxonomyMappings' fields
      2. Add the Top25 entries to Top25Examples field 
      3. Save as JSON and JSONL files
   3. output
      1. data_out/cwe_updated.json
      2. data_out/cwe_updated.jsonl
