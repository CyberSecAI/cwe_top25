import csv
import re

def convert_csv(input_file, output_file):
    with open(input_file, 'r') as infile, open(output_file, 'w', newline='') as outfile:
        reader = csv.reader(infile)
        writer = csv.writer(outfile)
        
        # Write the header for the new CSV
        writer.writerow(['CVE', 'ROOTCAUSE', 'WEAKNESS', 'IMPACT', 'VECTOR', 'ATTACKER', 'PRODUCT', 'VERSION', 'COMPONENT'])
        
        # Skip the header of the input file
        next(reader)
        
        for row in reader:
            cve = row[0]
            key_entities = row[1]
            
            # Initialize variables for each field
            rootcause = weakness = impact = vector = attacker = product = version = component = ""
            
            # Extract information using regex
            rootcause_match = re.search(r'\[ROOTCAUSE\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            weakness_match = re.search(r'\[WEAKNESS\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            impact_match = re.search(r'\[IMPACT\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            vector_match = re.search(r'\[VECTOR\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            attacker_match = re.search(r'\[ATTACKER\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            product_match = re.search(r'\[PRODUCT\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            version_match = re.search(r'\[VERSION\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            component_match = re.search(r'\[COMPONENT\]\s*(.*?)(?=\s*\[|\Z)', key_entities)
            
            # Assign extracted values if matches are found
            if rootcause_match: rootcause = rootcause_match.group(1).strip()
            if weakness_match: weakness = weakness_match.group(1).strip()
            if impact_match: impact = impact_match.group(1).strip()
            if vector_match: vector = vector_match.group(1).strip()
            if attacker_match: attacker = attacker_match.group(1).strip()
            if product_match: product = product_match.group(1).strip()
            if version_match: version = version_match.group(1).strip()
            if component_match: component = component_match.group(1).strip()
            
            # Write the new row
            writer.writerow([cve, rootcause, weakness, impact, vector, attacker, product, version, component])

    print(f"Conversion complete. Output written to {output_file}")

# Usage
input_file = 'data_out/CVE_KeyEntities.csv'
output_file = 'data_out/KeyEntities.csv'
convert_csv(input_file, output_file)