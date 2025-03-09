# VULNERABILITIES

## 1. Unrestricted File Upload in Video Processing

### Vulnerability name
Unrestricted File Upload in Video Processing

### Description
The application allows users to upload video files that are subsequently processed into screenshots without proper validation of the file content, size, or format. The video processing functionality in `video/utils.py` accepts base64-encoded data URLs from users and writes them directly to the file system before processing.

Step by step to trigger vulnerability:
1. Connect to the WebSocket endpoint at `/generate-code`
2. Provide a malicious video file encoded as a base64 data URL in the `image` parameter
3. Set `inputMode` to "video"
4. The server decodes the data URL without proper validation
5. The decoded content is written to a temporary file using `tempfile.NamedTemporaryFile`
6. The temporary file is processed using the `VideoFileClip` function from the `moviepy` library

### Impact
This vulnerability allows attackers to upload specially crafted video files that could potentially:
- Exploit vulnerabilities in the video processing libraries (MoviePy, FFmpeg)
- Cause excessive resource consumption by uploading extremely large or malformed files
- Potentially achieve remote code execution if the underlying libraries have unpatched vulnerabilities

The severity is high because it could lead to remote code execution on the server.

### Vulnerability rank
High

### Currently implemented mitigations
There are no effective mitigations implemented. The code uses `tempfile.NamedTemporaryFile` with `delete=True` which helps clean up the temporary file after processing, but this doesn't prevent the vulnerability from being exploited.

### Missing mitigations
1. File type validation based on content inspection, not just MIME type
2. File size limitations to prevent excessive resource consumption
3. Content validation before processing
4. Sandboxing the video processing operation
5. Rate limiting video uploads

### Preconditions
- The attacker must have access to the WebSocket endpoint `/generate-code`
- The video processing feature must be enabled

### Source code analysis
The vulnerability exists in the `video/utils.py` file:

```python
def split_video_into_screenshots(video_data_url: str) -> list[Image.Image]:
    # Decode the base64 URL to get the video bytes
    video_encoded_data = video_data_url.split(",")[1]
    video_bytes = base64.b64decode(video_encoded_data)

    mime_type = video_data_url.split(";")[0].split(":")[1]
    suffix = mimetypes.guess_extension(mime_type)

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=True) as temp_video_file:
        print(temp_video_file.name)
        temp_video_file.write(video_bytes)
        temp_video_file.flush()
        clip = VideoFileClip(temp_video_file.name)
        # ... processing continues ...
```

The key issues are:
1. The function accepts any base64-encoded data URL without validation
2. The MIME type is extracted from the data URL, which can be easily forged
3. The suffix for the temporary file is determined using `mimetypes.guess_extension(mime_type)` without verifying that it matches the actual content
4. The decoded bytes are written to the file system without any content validation
5. The `VideoFileClip` function is called on the temporary file, which could process malicious content

This vulnerability is triggered via the WebSocket endpoint in `routes/generate_code.py` when `input_mode` is set to "video":

```python
if input_mode == "video":
    video_data_url = params["image"]
    prompt_messages = await assemble_claude_prompt_video(video_data_url)
```

The `assemble_claude_prompt_video` function then calls `split_video_into_screenshots` with the user-provided data URL.

### Security test case
1. Create a specially crafted malicious video file (e.g., a file with a known FFmpeg vulnerability)
2. Encode the file as a base64 data URL: `data:video/mp4;base64,<base64-encoded malicious content>`
3. Connect to the WebSocket endpoint at `/generate-code`
4. Send a JSON payload with:
   ```json
   {
     "image": "data:video/mp4;base64,<base64-encoded malicious content>",
     "inputMode": "video",
     "generatedCodeConfig": "html_tailwind",
     "generationType": "create"
   }
   ```
5. Observe if the server experiences abnormal behavior, crashes, or executes unexpected code

This test case verifies if the server is vulnerable to malicious video file uploads that could exploit vulnerabilities in the video processing libraries.

## 2. Path Traversal in Evaluation Routes

### Vulnerability name
Path Traversal in Evaluation Routes

### Description
The evaluation endpoints (`/evals`, `/pairwise-evals`, `/best-of-n-evals`) accept user-provided folder paths and use them to access files on the server's filesystem without proper validation or sanitization. An attacker can use directory traversal sequences (like `../`) to access files outside the intended directories.

Step by step to trigger vulnerability:
1. Identify one of the evaluation endpoints (e.g., `/evals`)
2. Craft a request with a folder parameter containing path traversal sequences (e.g., `?folder=../../../etc`)
3. The application attempts to access files in the specified directory
4. The application returns file contents or information that should not be accessible

### Impact
This vulnerability could allow an attacker to:
- Read sensitive configuration files (like `.env` files containing API keys)
- Access system files containing sensitive information
- Map the server's directory structure
- Read source code files that might contain hardcoded credentials or security vulnerabilities

The severity is high because it could lead to unauthorized access to sensitive information.

### Vulnerability rank
High

### Currently implemented mitigations
The code checks if the provided folder exists but doesn't validate that it's within an allowed directory:
```python
folder_path = Path(folder)
if not folder_path.exists():
    raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")
```

### Missing mitigations
1. Path sanitization to remove traversal sequences
2. Path normalization followed by validation against allowed directories
3. Use of a whitelist approach where only predefined folders are allowed
4. Implementation of proper access controls for evaluation endpoints

### Preconditions
- The evaluation endpoints must be publicly accessible
- The attacker must be able to make HTTP requests to these endpoints

### Source code analysis
The vulnerability exists in `routes/evals.py`. For example, in the `get_evals` function:

```python
@router.get("/evals", response_model=list[Eval])
async def get_evals(folder: str):
    if not folder:
        raise HTTPException(status_code=400, detail="Folder path is required")

    folder_path = Path(folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail=f"Folder not found: {folder}")

    try:
        evals: list[Eval] = []
        # Get all HTML files from folder
        files = {
            f: os.path.join(folder, f)
            for f in os.listdir(folder)
            if f.endswith(".html")
        }
        # ... continues processing files ...
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing evals: {str(e)}")
```

The function accepts a user-provided `folder` parameter without any validation or sanitization beyond checking if it exists. It then uses `os.listdir(folder)` to list files in the directory and `os.path.join(folder, f)` to construct file paths.

Similarly, in the `get_pairwise_evals` function:

```python
@router.get("/pairwise-evals", response_model=PairwiseEvalResponse)
async def get_pairwise_evals(
    folder1: str = Query(
        "...",
        description="Absolute path to first folder",
    ),
    folder2: str = Query(
        "..",
        description="Absolute path to second folder",
    ),
):
    if not os.path.exists(folder1) or not os.path.exists(folder2):
        return {"error": "One or both folders do not exist"}
    # ... continues processing files from both folders ...
```

The function accepts two user-provided folder paths and uses them to access files without proper validation.

The same issue exists in the `get_best_of_n_evals` function, which extracts folder paths from query parameters and uses them to access files without validation.

### Security test case
1. Identify the evaluation endpoints:
   - `/evals`
   - `/pairwise-evals`
   - `/best-of-n-evals`

2. For the `/evals` endpoint:
   - Send a request: `GET /evals?folder=../../../etc`
   - Check if the response contains information about files in the `/etc` directory

3. For the `/pairwise-evals` endpoint:
   - Send a request: `GET /pairwise-evals?folder1=../../../etc&folder2=../../../var`
   - Check if the response contains information from both directories

4. For the `/best-of-n-evals` endpoint:
   - Send a request: `GET /best-of-n-evals?folder1=../../../etc&folder2=../../../var`
   - Check if the response contains information from both directories

5. Try accessing specific sensitive files:
   - `GET /evals?folder=../../.env` (to access API keys)
   - `GET /evals?folder=../` (to access the parent directory)

This test case verifies if the application is vulnerable to path traversal attacks by attempting to access directories and files outside the intended directory structure.

## 3. Prompt Injection in Image Generation

### Vulnerability name
Prompt Injection in Image Generation

### Description
The application uses user-generated content as input for AI image generation, without sufficient filtering or validation. Specifically, alt text from HTML images is extracted and used as prompts for DALL-E 3 or Flux image generation APIs. An attacker can craft a screenshot or request that manipulates the AI into generating code with malicious alt text, which is then used to generate potentially harmful or inappropriate images.

Step by step to trigger vulnerability:
1. Create a screenshot or request that contains elements designed to manipulate the AI
2. Send this input to the application's code generation endpoint
3. The AI generates HTML code with image tags containing attacker-controlled alt text
4. The application extracts these alt texts and uses them as prompts for image generation
5. Malicious or inappropriate images are generated using the third-party image generation API

### Impact
This vulnerability could allow attackers to:
- Generate offensive, inappropriate, or illegal images through the application
- Bypass content filters by crafting prompts that appear benign but produce harmful content
- Potentially cause reputational damage to the service provider
- Generate images that could create legal liability for the service provider (copyright infringement, inappropriate content, etc.)
- Increase costs by generating unnecessary or malicious images through paid APIs

### Vulnerability rank
High

### Currently implemented mitigations
The application does not implement any content filtering or validation for the alt text used as image generation prompts.

### Missing mitigations
1. Content filtering for image alt text before using it as prompts
2. Rate limiting for image generation requests
3. Prompt sanitization to remove potentially harmful instructions
4. Implementation of a prompt allow-list or pattern validation
5. Human review for generated images in sensitive contexts

### Preconditions
- The attacker must be able to provide input to the code generation endpoint
- Image generation must be enabled (controlled by the `should_generate_images` parameter)
- The application must be configured with valid API keys for image generation services

### Source code analysis
The vulnerability exists in the interaction between the code generation and image generation components. In `image_generation/core.py`, the `generate_images` function:

```python
async def generate_images(
    code: str,
    api_key: str,
    base_url: Union[str, None],
    image_cache: Dict[str, str],
    model: Literal["dalle3", "flux"] = "dalle3",
) -> str:
    # Find all images
    soup = BeautifulSoup(code, "html.parser")
    images = soup.find_all("img")

    # Extract alt texts as image prompts
    alts: List[str | None] = []
    for img in images:
        # Only include URL if the image starts with https://placehold.co
        # and it's not already in the image_cache
        if (
            img["src"].startswith("https://placehold.co")
            and image_cache.get(img.get("alt")) is None
        ):
            alts.append(img.get("alt", None))

    # Exclude images with no alt text
    filtered_alts: List[str] = [alt for alt in alts if alt is not None]

    # Remove duplicates
    prompts = list(set(filtered_alts))

    # Return early if there are no images to replace
    if len(prompts) == 0:
        return code

    # Generate images
    results = await process_tasks(prompts, api_key, base_url, model)
```

This function extracts alt text from images in the generated HTML code and uses them directly as prompts for image generation via the `process_tasks` function.

The `process_tasks` function then calls either `generate_image_dalle` or `generate_image_replicate` depending on the model:

```python
async def process_tasks(
    prompts: List[str],
    api_key: str,
    base_url: str | None,
    model: Literal["dalle3", "flux"],
):
    if model == "dalle3":
        tasks = [generate_image_dalle(prompt, api_key, base_url) for prompt in prompts]
    else:
        tasks = [generate_image_replicate(prompt, api_key) for prompt in prompts]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    # ... process results ...
    return processed_results
```

These functions directly send the extracted alt text as prompts to the respective image generation APIs:

```python
async def generate_image_dalle(
    prompt: str, api_key: str, base_url: str | None
) -> Union[str, None]:
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    res = await client.images.generate(
        model="dall-e-3",
        quality="standard",
        style="natural",
        n=1,
        size="1024x1024",
        prompt=prompt,
    )
    await client.close()
    return res.data[0].url
```

The critical issue is that alt text from the generated HTML (which is influenced by user input) is directly used as prompts for image generation without validation or filtering.

### Security test case
1. Create a carefully crafted input designed to manipulate the code generation AI into producing HTML with malicious alt text
2. Example input:
   ```
   Create a webpage with an image. The alt text for the image should be: "A picture of [insert inappropriate content description here] in photorealistic style"
   ```

3. Send this input to the WebSocket endpoint at `/generate-code` with parameters:
   ```json
   {
     "image": "[data URL of crafted input]",
     "inputMode": "image",
     "generatedCodeConfig": "html_tailwind",
     "generationType": "create",
     "isImageGenerationEnabled": true
   }
   ```

4. Observe the generated code to confirm that it contains image tags with the injected alt text
5. Verify if the application uses these alt texts as prompts for image generation
6. Check if inappropriate or harmful images are generated as a result

This test case verifies if an attacker can manipulate the code generation AI to produce alt text that bypasses content filters and results in the generation of inappropriate or malicious images.
