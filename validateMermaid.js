import mermaid from 'mermaid';
import jsdom from 'jsdom';
import createDOMPurify from 'dompurify';

const { JSDOM } = jsdom;

const validateMermaidDiagram = async (mermaidCode) => {
  try {
    // Setup DOM environment with all required options
    const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
      url: 'http://localhost',
      referrer: "http://localhost",
      contentType: "text/html",
      includeNodeLocations: true,
      runScripts: "dangerously",
      resources: "usable"
    });

    // Set up the global variables
    const window = dom.window;
    const document = window.document;

    // Create DOMPurify instance
    const DOMPurify = createDOMPurify(window);

    // Set globals that mermaid needs
    global.window = window;
    global.document = document;
    global.DOMPurify = DOMPurify;

    // Initialize mermaid with all required settings
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'loose',
      theme: 'default'
    });

    // Await the parse result
    await mermaid.parse(mermaidCode);
    return { isValid: true, error: null };
  } catch (error) {
    return { isValid: false, error: error.message };
  }
};

const mermaidCode = process.argv[2];
if (!mermaidCode) {
    console.error("Error: No Mermaid code provided.");
    process.exit(1); // Failure exit
}

// Validate the Mermaid code
const result = validateMermaidDiagram(mermaidCode);

result.then((value) => {
    if (!value.isValid) {
        console.error(value.error);
        process.exit(1);
    }
    process.exit(0);
})
.catch((e) => {
    console.error(e);
    process.exit(1);
})
