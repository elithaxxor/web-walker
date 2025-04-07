"""
LLMAnalyzer - A class for integrating with Hugging Face's Transformers library.

This class provides methods for performing text analysis using large language models (LLMs),
specifically supporting sentiment analysis and named entity recognition (NER).
"""

try:
    from transformers import pipeline
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False

class LLMAnalyzer:
    """
    A class to analyze text using Hugging Face's Transformers library.

    Attributes:
        pipeline (transformers.Pipeline): The Hugging Face pipeline for the specified model.
    """

    def __init__(self, model_name: str):
        """
        Initialize the LLMAnalyzer with a specified model.

        Args:
            model_name (str): The type of model to use ('sentiment' or 'ner').

        Raises:
            ImportError: If the transformers library is not installed.
            ValueError: If an unsupported model name is provided.
        """
        if not LLM_AVAILABLE:
            raise ImportError("Transformers library not installed. Install with 'pip install transformers'.")
        
        if model_name == "sentiment":
            self.pipeline = pipeline("sentiment-analysis")
        elif model_name == "ner":
            self.pipeline = pipeline("ner", model="dbmdz/bert-large-cased-finetuned-conll03-english")
        else:
            raise ValueError(f"Unsupported model: {model_name}")

    def analyze(self, text: str) -> list:
        """
        Analyze the provided text using the specified LLM pipeline.

        Args:
            text (str): The text to analyze.

        Returns:
            list: The analysis results (e.g., sentiment scores or NER entities).
                  Returns an empty list if no text is provided or if analysis fails.
        """
        if not text:
            return []
        try:
            return self.pipeline(text)
        except Exception as e:
            print(f"Error during analysis: {e}")
            return []
