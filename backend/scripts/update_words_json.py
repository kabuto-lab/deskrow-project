import json
import csv

def update_words_json():
    # Read adjectives from existing words.json
    adjectives = []
    with open('frontend/static/js/words.json', 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            adjectives = data.get('adjectives', [])
        except json.JSONDecodeError:
            print("Warning: Couldn't parse words.json, using empty adjectives list")

    # Read nouns from processed_nouns.csv
    nouns = []
    with open('processed_nouns.csv', 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        nouns = [row[0] for row in reader]

    # Create new data structure
    new_data = {
        "adjectives": adjectives,
        "nouns": nouns
    }

    # Write updated file
    with open('frontend/static/js/words.json', 'w', encoding='utf-8') as f:
        json.dump(new_data, f, indent=2)

if __name__ == '__main__':
    update_words_json()
