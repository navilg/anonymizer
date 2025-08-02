from presidio_analyzer import AnalyzerEngine

def basic_analyzer(text):
    """
    Analyze text and return detected PII entities
    
    Args:
        text (str): Input text to analyze
        
    Returns:
        list: List of detected entities with details
    """
    # Initialize the analyzer
    analyzer = AnalyzerEngine()
    
    # Analyze the text
    results = analyzer.analyze(text=text, language="en")
    
    # Format results for easy reading
    detected_entities = []
    
    for result in results:
        entity_info = {
            "entity_type": result.entity_type,
            "confidence": round(result.score, 3),
            "start": result.start,
            "end": result.end,
            "text": text[result.start:result.end]
        }
        detected_entities.append(entity_info)
    
    return detected_entities

# Example usage
if __name__ == "__main__":
    sentence = str(input("Enter a sentence: "))
    print(f"Text: {sentence}")
    print("Detected Entities:")
        
    entities = basic_analyzer(sentence)
        
    if entities:
        for entity in entities:
            print(f"  - {entity['entity_type']}: '{entity['text']}' "
                f"(confidence: {entity['confidence']})")
    else:
        print("  No entities detected")
        
    print("-" * 50)
