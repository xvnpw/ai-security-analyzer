from langchain_core.documents import Document

from ai_security_analyzer.documents import DocumentProcessor, DocumentFilter


# Mock Tokenizer for testing
class MockTokenizer:
    def encode(self, text):
        # Simple tokenizer that splits text by spaces
        return text.strip().split()


def test_get_docs_batch():
    tokenizer = MockTokenizer()
    processor = DocumentProcessor(tokenizer=tokenizer)

    # Create test documents
    doc1 = Document(page_content="This is a test.", metadata={"source": "doc1.txt"})
    doc2 = Document(page_content="This is another test document.", metadata={"source": "doc2.txt"})
    doc3 = Document(
        page_content="This document is longer and should not fit in the context window.",
        metadata={"source": "doc3.txt"},
    )
    documents = [doc1, doc2, doc3]

    # Set context window to allow only doc1 and doc2
    context_window = len(tokenizer.encode(doc1.page_content)) + len(tokenizer.encode(doc2.page_content))

    batch = processor.get_docs_batch(documents, context_window)

    assert batch == [doc1, doc2], "Batch should contain doc1 and doc2"


def test_format_docs_for_prompt():
    tokenizer = MockTokenizer()
    processor = DocumentProcessor(tokenizer=tokenizer)

    doc1 = Document(page_content="Content of doc1", metadata={"source": "doc1.txt"})
    doc2 = Document(page_content="Content of doc2", metadata={"source": "doc2.txt"})
    documents = [doc1, doc2]

    expected_output = (
        f"File: doc1.txt\nContent:\nContent of doc1\n{'=' * 80}\n"
        f"File: doc2.txt\nContent:\nContent of doc2\n{'=' * 80}"
    )

    output = processor.format_docs_for_prompt(documents)

    assert output == expected_output, "Formatted output does not match expected output"


def test_sort_and_filter_docs_no_keywords():
    doc1 = Document(page_content="Content of README", metadata={"source": "README.md"})
    doc2 = Document(page_content="Content of a markdown file", metadata={"source": "file.md"})
    doc3 = Document(page_content="Content of a text file", metadata={"source": "file.txt"})
    documents = [doc3, doc2, doc1]

    doc_filter = DocumentFilter()
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=None)

    assert sorted_docs == [doc1, doc2, doc3], "Documents should be sorted with README.md first, then .md files"


def test_sort_and_filter_docs_with_keywords():
    doc1 = Document(page_content="Important content here", metadata={"source": "README.md"})
    doc2 = Document(page_content="This document contains the keyword", metadata={"source": "file.md"})
    doc3 = Document(page_content="No relevant content", metadata={"source": "file.txt"})
    keywords = {"keyword", "important"}
    documents = [doc3, doc2, doc1]

    doc_filter = DocumentFilter()
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=keywords)

    assert sorted_docs == [
        doc1,
        doc2,
    ], "Only documents containing keywords or README.md should be included and sorted correctly"


def test_get_docs_batch_exceeding_context():
    tokenizer = MockTokenizer()
    processor = DocumentProcessor(tokenizer=tokenizer)

    # Create test documents
    doc1 = Document(page_content="Word " * 10, metadata={"source": "doc1.txt"})  # 10 tokens
    doc2 = Document(page_content="Word " * 20, metadata={"source": "doc2.txt"})  # 20 tokens
    doc3 = Document(page_content="Word " * 30, metadata={"source": "doc3.txt"})  # 30 tokens
    documents = [doc1, doc2, doc3]

    # Set context window to allow only doc1
    context_window = 15  # Only doc1 should fit
    batch = processor.get_docs_batch(documents, context_window)
    assert batch == [doc1], "Batch should contain only doc1"


def test_format_docs_for_prompt_empty():
    tokenizer = MockTokenizer()
    processor = DocumentProcessor(tokenizer=tokenizer)

    documents = []
    output = processor.format_docs_for_prompt(documents)
    assert output == "", "Output should be empty for empty documents list"


def test_sort_and_filter_docs_no_documents():
    documents = []
    keywords = {"test"}
    doc_filter = DocumentFilter()
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=keywords)
    assert sorted_docs == [], "Sorted docs should be empty when input documents list is empty"


def test_sort_and_filter_docs_no_matching_keywords():
    doc1 = Document(page_content="Content without keywords", metadata={"source": "file1.txt"})
    doc2 = Document(page_content="More content without the keywords", metadata={"source": "file2.txt"})
    documents = [doc1, doc2]
    keywords = {"nonexistent"}

    doc_filter = DocumentFilter()
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=keywords)
    assert sorted_docs == [], "No documents should be returned when no documents contain the keywords"


def test_sort_and_filter_docs_case_insensitive_keywords():
    doc = Document(page_content="Content with Keyword", metadata={"source": "file.txt"})
    documents = [doc]
    keywords = {"keyword"}

    doc_filter = DocumentFilter()
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=keywords)
    assert sorted_docs == [doc], "Keyword matching should be case-insensitive"


def test_sort_and_filter_docs_missing_metadata():
    doc1 = Document(page_content="Content with keyword", metadata={})
    doc2 = Document(page_content="Content without it", metadata={})
    documents = [doc1, doc2]
    keywords = {"keyword"}

    doc_filter = DocumentFilter()
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=keywords)
    assert sorted_docs == [doc1], "Documents should be filtered based on content even if metadata is missing"


def test_get_docs_batch_no_documents():
    tokenizer = MockTokenizer()
    processor = DocumentProcessor(tokenizer=tokenizer)
    documents = []
    context_window = 10
    batch = processor.get_docs_batch(documents, context_window)
    assert batch == [], "Batch should be empty when input documents list is empty"


def test_get_docs_batch_zero_context_window():
    tokenizer = MockTokenizer()
    processor = DocumentProcessor(tokenizer=tokenizer)
    doc = Document(page_content="Test content", metadata={"source": "doc.txt"})
    documents = [doc]
    context_window = 0
    batch = processor.get_docs_batch(documents, context_window)
    assert batch == [], "Batch should be empty when context window is zero"


def test_sort_and_filter_docs_with_shuffle():
    # Create multiple docs of different types to test shuffling
    readme_doc = Document(page_content="README content", metadata={"source": "README.md"})
    md_doc1 = Document(page_content="Markdown content 1", metadata={"source": "file1.md"})
    md_doc2 = Document(page_content="Markdown content 2", metadata={"source": "file2.md"})
    txt_doc1 = Document(page_content="Text content 1", metadata={"source": "file1.txt"})
    txt_doc2 = Document(page_content="Text content 2", metadata={"source": "file2.txt"})

    documents = [txt_doc1, md_doc1, txt_doc2, readme_doc, md_doc2]

    # Call with shuffle=True
    doc_filter = DocumentFilter(shuffle=True)
    sorted_docs = doc_filter.sort_and_filter_docs(documents, keywords=None)

    # Verify README.md is still first despite shuffling
    assert sorted_docs[0] == readme_doc, "README.md document should always be first despite shuffling"

    # Verify remaining docs are still in proper type order (md files before txt files)
    md_files = [doc for doc in sorted_docs[1:] if doc.metadata.get("source", "").endswith(".md")]
    txt_files = [doc for doc in sorted_docs[1:] if doc.metadata.get("source", "").endswith(".txt")]

    # All md files should come before all txt files in the sorted list
    last_md_index = max([sorted_docs.index(doc) for doc in md_files]) if md_files else 0
    first_txt_index = min([sorted_docs.index(doc) for doc in txt_files]) if txt_files else len(sorted_docs)

    assert last_md_index < first_txt_index, "All markdown files should come before text files after sorting"

    # Verify all documents are still present
    assert len(sorted_docs) == len(documents), "Number of documents should remain the same"
    for doc in documents:
        assert doc in sorted_docs, f"Document {doc.metadata.get('source')} should be present in the sorted documents"
