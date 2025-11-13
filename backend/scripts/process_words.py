import csv
import json
import re
from pathlib import Path

# List of negative/abusive adjectives to remove
NEGATIVE_ADJECTIVES = {
    'nasty', 'stupid', 'ugly', 'crazy', 'mad', 'dumb', 'gross', 'sick',
    'dirty', 'dead', 'ill', 'drunk', 'sad', 'unhappy', 'angry', 'afraid',
    'scared', 'anxious', 'nervous', 'guilty', 'lonely', 'embarrassed'
}

VOWEL_PATTERN = re.compile(r'[aeiou]{2,}', re.IGNORECASE)

def load_adjectives(csv_path):
    """Load adjectives from CSV file and remove duplicates"""
    adjectives = set()
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for row in reader:
            if row:  # Skip empty rows
                adj = row[0].strip().lower()
                if adj:  # Skip empty strings
                    adjectives.add(adj)
    return adjectives

def filter_adjectives(adjectives):
    """Filter out negative adjectives"""
    return [adj for adj in adjectives 
            if adj.lower() not in NEGATIVE_ADJECTIVES]

def filter_nouns(nouns):
    """Filter out nouns with 2+ consecutive vowels"""
    return [noun for noun in nouns 
            if not VOWEL_PATTERN.search(noun)]

def main():
    csv_path = Path('.adjectives_add1.csv')
    json_path = Path('frontend/static/js/words.json')
    
    # Load existing data preserving all fields
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Process adjectives
    existing_adjs = set(adj.lower() for adj in data.get('adjectives', []))
    new_adjs = load_adjectives(csv_path)
    to_add = new_adjs - existing_adjs
    
    if to_add:
        current_adjs = data.get('adjectives', [])
        current_adjs.extend([adj for adj in new_adjs if adj.lower() in to_add])
        data['adjectives'] = filter_adjectives(current_adjs)
    
    # Process nouns if they exist
    if 'nouns' in data:
        data['nouns'] = filter_nouns(data['nouns'])
    
    # Write back to file preserving all data
    with open(json_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    adj_count = len(data.get('adjectives', []))
    noun_count = len(data.get('nouns', []))
    print(f"Updated words.json with {adj_count} adjectives and {noun_count} nouns")

if __name__ == '__main__':
    main()
