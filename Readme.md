
# Overview
1. Do Exploratory Data Analysis (EDA) on Top 25 CWEs file from MITRE CWE
2. Add CVE Descriptions to Top 25 and remove Rationale, and CWE entries that are not a CWE
3. Add Top25 Known Good CVE-CWE Mappings to CWE JSON as Top25Examples

## Do Exploratory Data Analysis (EDA) on Top 25 CWEs file from MITRE CWE

1. [top25_eda.ipynb](top25_eda.ipynb)
   1. Output: 
      1. [reports/top25-mitre-mapping-analysis-2023-public.html](reports/top25-mitre-mapping-analysis-2023-public.html)


## Add CVE Descriptions to Top 25 and remove Rationale, and CWE entries that are not a CWE

1. [nvd/CVSSData.ipynb](nvd/CVSSData.ipynb) gets the CVE Descriptions from NVD JSON files
2. [top25_add_cve_desc.ipynb](top25_add_cve_desc.ipynb) adds CVE Descriptions to Top 25 entries
   1. Remove Rationale Column from MITRE CWE
   1. Remove entries where CWE is not a CWE e.g. NVD-CWE-Insufficient-Info (593), UNSURE (476), CWE-RESEARCH (117),...
      1. this reduces the number of entries from 9712 to 8522
   2. output: ./data_out/top25-mitre-mapping-analysis-2023-public_with_cve_descriptions.csv




## Add Top25 Known Good CVE-CWE Mappings to CWE JSON as Top25Examples

1. download CWE JSON
   1. wget https://raw.githubusercontent.com/CWE-CAPEC/REST-API-wg/main/json_repo/cwe.json  
2. cwe_json.ipynb
   1. input: 
      1. ./data_in/cwe.json  
      2. ./data_out/top25-mitre-mapping-analysis-2023-public_with_cve_descriptions.csv
   2. steps
      1. remove 'ContentHistory', 'Views', 'Categories', 'References', 'TaxonomyMappings' fields
      3. Save as JSON and JSONL files
         1. data_out/cwe_trimmed.json
         2. data_out/cwe_trimmed.jsonl
      4. Add the Top25 entries to Top25Examples field 
      5. Save as JSON and JSONL files
         1. data_out/cwe_trimmed_top25.json
         2. data_out/cwe_trimmed_top25.jsonl
         3. data_out/output_jsonl/ contains several files which are cwe_trimmed_top25.jsonl split into smaller files and renamed with txt extension. 


## Prohibited and Deprecated
The Prohibited and Deprecated CWE entries were not removed

* 84 entries with "Usage": "Prohibited"
  * of which 25 entries with"Status": "Deprecated"


