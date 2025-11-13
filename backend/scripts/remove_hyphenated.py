import json
from pathlib import Path

def remove_hyphenated(words):
    """Remove words containing hyphens"""
    return [word for word in words if '-' not in word]

def main():
    json_path = Path('frontend/static/js/words.json')
    
    # Load existing data
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    changes_made = False
    
    # Process adjectives
    if 'adjectives' in data:
        original_count = len(data['adjectives'])
        data['adjectives'] = remove_hyphenated(data['adjectives'])
        removed = original_count - len(data['adjectives'])
        if removed > 0:
            print(f"Removed {removed} hyphenated adjectives")
            changes_made = True
    
    # Process nouns
    if 'nouns' in data:
        original_count = len(data['nouns'])
        data['nouns'] = remove_hyphenated(data['nouns'])
        removed = original_count - len(data['nouns'])
        if removed > 0:
            print(f"Removed {removed} hyphenated nouns") 
            changes_made = True
    
    # Save if changes were made
    if changes_made:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print("Updated words.json")
    else:
        print("No hyphenated words found")

if __name__ == '__main__':
    main()
