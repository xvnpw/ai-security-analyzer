# User stories

## User can run `fabric` withing Github issues

As a GitHub user, I want to be able to use a GitHub action to leverage a large language model (LLM) from the [fabric](https://github.com/danielmiessler/fabric) app to perform various actions on GitHub issues, so that I can automate and streamline my workflow.

**Acceptance Criteria:**

1. The GitHub action should be able to detect when a user adds a comment to a GitHub issue that starts with the keyword "fabric".
2. The action should be able to parse the rest of the comment to determine the specific action the user wants to perform, such as "create stride threat model".
3. The action should then pass the relevant information from the issue (e.g., the issue body in Markdown format) to the `fabric`, which will process the request and generate the appropriate output.
4. The action should then post the output as a new comment on the original GitHub issue.
5. The action should handle any errors or failures gracefully, providing the user with a clear indication of what went wrong.

## User can run `fabric` with references to additional files in repository

As a GitHub user, I want the GitHub action to be able to fetch additional files from the repository, along with the issue information, so that I can provide the fabric with a more comprehensive set of data to process my requests.

**Acceptance Criteria:**

1. The GitHub action should be able to detect when a user adds a comment to a GitHub issue that starts with the keyword "fabric" and includes a request to fetch additional files.
2. The action should be able to parse the comment to determine the specific files the user wants to fetch, in addition to the action they want to perform (e.g., "fabric, create stride threat model from this issue and the threat_model.md file").
3. The action should then use the GitHub API to fetch the specified files from the repository.
4. The action should combine the issue information (e.g., the issue body in Markdown format) and the fetched files, and pass this data to the fabric for processing.
5. The action should then post the output from the fabric as a new comment on the original GitHub issue.
6. The action should handle any errors or failures gracefully, providing the user with a clear indication of what went wrong (e.g., if a requested file does not exist).

## User can edit issue and re-run `fabric`

As a GitHub user, I want to be able to edit the content of a GitHub issue after the initial fabric processing has been performed, and then ask the GitHub action to re-run the fabric processing on the updated issue, so that I can refine my request and get updated results.

**Acceptance Criteria:**

1. The GitHub action should be able to detect when a user adds a comment to a GitHub issue that starts with the keyword "fabric" and includes a request to re-run the fabric processing (e.g., "fabric, re-process this issue").
2. The action should be able to identify the previous fabric processing that was performed on the issue, and use the original issue content and any fetched files to re-send the request to the fabric.
3. If the user has edited the issue content since the last fabric processing, the action should use the updated issue content and any previously fetched files for the re-processing.
4. The action should post the new output from the fabric as a new comment on the original GitHub issue.
5. The action should handle any errors or failures gracefully, providing the user with a clear indication of what went wrong (e.g., if the fabric returns an error).

## User can run chained `fabric` calls

As a GitHub user, I want to be able to submit a series of fabric requests that can be executed in sequence, so that I can perform more complex workflows or multi-step processes on the GitHub issue content.

**Acceptance Criteria:**

1. The GitHub action should be able to detect when a user adds a comment to a GitHub issue that starts with the keyword "fabric" and includes a sequence of requests (e.g., "fabric, create stride threat model, then summarize the threat model").
2. The action should be able to parse the sequence of requests and execute them one after the other, passing the output of the previous request as input to the next request.
3. If the user includes a request to fetch additional files, the action should fetch those files and include them in the input data for the subsequent requests.
4. The action should post the final output from the sequence of fabric requests as a new comment on the original GitHub issue.
5. The action should handle any errors or failures gracefully, providing the user with a clear indication of what went wrong (e.g., if one of the requests in the sequence fails).
