import re
import json
from pathlib import Path

def process_nouns():
    # Paths
    project_root = Path(__file__).parent.parent.parent
    csv_path = project_root / 'noun.csv'
    json_path = project_root / 'frontend' / 'static' / 'js' / 'words.json'
    
    # Read and process CSV
    nouns = set()
    with open(csv_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
                
            # Split by commas and take first string
            parts = [part.strip() for part in line.split(',')]
            if not parts:
                continue
                
            first_string = parts[0]
            words = first_string.split()
            
            # Check for single word case
            if len(words) == 1:
                word = words[0]
                if re.fullmatch(r'^[a-zA-Z]+$', word) and len(word) >= 5 and len(word)<10:
                    nouns.add(word.lower())
                    
            # Check for two word case
            elif len(words) == 2:
                word = words[1]  # Take second word
                if re.fullmatch(r'^[a-zA-Z]+$', word) and len(word) >= 4 and len(word)<10:
                    nouns.add(word.lower())
    
    # Read existing words.json
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Replace existing nouns with processed nouns (keeping adjectives unchanged)
    data['nouns'] = sorted(nouns)
    
    # Write back to words.json
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    print(f"Processed {len(nouns)} nouns in words.json")

if __name__ == '__main__':
    process_nouns()
