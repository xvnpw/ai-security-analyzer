#!/usr/bin/env python3
import os


def main():
    examples_dir = "examples"

    # Our data structure will group files by mode, project, model and document type.
    # For most modes we store a single file per doc type.
    # For "github deep dive mode" we store a list of tuples (deep_flag, file_path)
    # so that we can record both base and deep analysis versions.
    data = {}

    modes = ["dir mode", "file mode", "github mode", "github deep dive mode"]
    mode_prefixes = {
        "dir mode": "dir-",
        "file mode": "file-",
        "github deep dive mode": "github-da-",
        "github mode": "github-",
    }

    # Mapping from document type slug (as found in filenames) to display text.
    doc_type_mapping = {
        "sec-design": "Security Design Review",
        "threat-modeling": "Threat Modeling",
        "attack-surface": "Attack Surface",
        "attack-tree": "Attack Tree",
        "mitigations": "Mitigation Strategies",
        "vulnerabilities": "Vulnerabilities",
        "vulnerabilitiesworkflow1": "Vulnerabilities Workflow 1",
    }
    # Order in which columns should appear.
    doc_order = [
        "sec-design",
        "threat-modeling",
        "attack-surface",
        "attack-tree",
        "mitigations",
        "vulnerabilities",
        "vulnerabilitiesworkflow1",
    ]

    # For each mode we know which projects are expected.
    mode_projects = {
        "dir mode": ["screenshot-to-code", "terraform-provider-chronicle"],
        "file mode": ["ai-nutrition-pro"],
        "github mode": ["flask", "screenshot-to-code"],
        "github deep dive mode": ["flask"],
    }

    # How to display (and link) the project names.
    project_display = {
        "screenshot-to-code": "screenshot-to-code",
        "ai-nutrition-pro": "AI-Nutrition-Pro",
        "flask": "flask",
        "terraform-provider-chronicle": "terraform-provider-chronicle",
    }
    project_links = {
        "screenshot-to-code": "https://github.com/abi/screenshot-to-code",
        "ai-nutrition-pro": "../tests/EXAMPLE_ARCHITECTURE.md",
        "flask": "https://github.com/pallets/flask",
        "terraform-provider-chronicle": "https://github.com/form3tech-oss/terraform-provider-chronicle",
    }

    # Initialize our data structure.
    for mode in modes:
        data[mode] = {}

    # Walk through the examples/ directory recursively.
    for root, dirs, files in os.walk(examples_dir):
        if root == "examples\\vulnerabilities-workflow":
            continue
        for filename in files:
            if not filename.endswith(".md"):
                continue
            if filename == "README.md":
                continue

            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, examples_dir)
            # Normalize path separators for Markdown (always use forward slashes)
            rel_path = rel_path.replace(os.sep, "/")

            # Determine the mode by matching filename prefix.
            mode = None
            prefix = None
            if filename.startswith(mode_prefixes["github deep dive mode"]):
                mode = "github deep dive mode"
                prefix = mode_prefixes["github deep dive mode"]
            elif filename.startswith(mode_prefixes["dir mode"]):
                mode = "dir mode"
                prefix = mode_prefixes["dir mode"]
            elif filename.startswith(mode_prefixes["file mode"]):
                mode = "file mode"
                prefix = mode_prefixes["file mode"]
            elif filename.startswith(mode_prefixes["github mode"]):
                mode = "github mode"
                prefix = mode_prefixes["github mode"]
            else:
                continue

            # Remove the mode-specific prefix.
            remainder = filename[len(prefix) :]
            # Determine the document type by checking for our known slugs.
            doc_type = None
            for dt in doc_type_mapping:
                if remainder.startswith(dt + "-"):
                    doc_type = dt
                    break
            if doc_type is None:
                continue

            # Remove the doc_type and following hyphen.
            remainder = remainder[len(doc_type) + 1 :]
            # Remove the .md extension.
            if remainder.endswith(".md"):
                remainder = remainder[:-3]

            # Expect remainder to be "project-model".
            project = None
            for proj in mode_projects.get(mode, []):
                if remainder.startswith(proj + "-"):
                    project = proj
                    break
                elif remainder == proj:
                    project = proj
                    break
            if project is None:
                parts = remainder.split("-", 1)
                if len(parts) == 2:
                    project, model = parts
                else:
                    continue
            else:
                model = remainder[len(project) + 1 :] if remainder.startswith(project + "-") else ""

            # For "github deep dive mode", check if the model ends with "-deep-analysis".
            # If so, remove that suffix and mark this file as a deep analysis version.
            deep = False
            if mode == "github deep dive mode":
                if model.endswith("-deep-analysis"):
                    deep = True
                    model = model[: -len("-deep-analysis")]

            # Store the file.
            if mode == "github deep dive mode":
                proj_dict = data[mode].setdefault(project, {})
                model_dict = proj_dict.setdefault(model, {})
                # For deep dive mode, store a list of entries per document type.
                model_dict.setdefault(doc_type, []).append((deep, rel_path))
            else:
                data[mode].setdefault(project, {}).setdefault(model, {})[doc_type] = rel_path

    # Now build the README.md content.
    lines = []
    lines.append("# Examples")
    lines.append("")

    for mode in modes:
        if not data[mode]:
            continue

        lines.append("## " + mode)
        lines.append("")
        for project in sorted(data[mode].keys(), key=lambda p: project_display.get(p, p)):
            display_name = project_display.get(project, project)
            link = project_links.get(project)
            if link:
                lines.append(f"Project: [{display_name}]({link})")
            else:
                lines.append(f"Project: {display_name}")
            lines.append("")
            lines.append("|  Model |  Documents |")
            lines.append("|---|---|")
            for model in sorted(data[mode][project].keys()):
                doc_links = []
                for dt in doc_order:
                    if dt in data[mode][project][model]:
                        if mode == "github deep dive mode":
                            # In deep dive mode we may have two entries per doc type.
                            # Sort so that the base version comes before the deep analysis one.
                            entries = sorted(data[mode][project][model][dt], key=lambda x: x[0])
                            for deep_flag, file_link in entries:
                                if deep_flag:
                                    display = doc_type_mapping[dt] + " - Deep Analysis"
                                else:
                                    display = doc_type_mapping[dt]
                                doc_links.append(f"[{display}]({file_link})")
                        else:
                            file_link = data[mode][project][model][dt]
                            doc_links.append(f"[{doc_type_mapping[dt]}]({file_link})")
                docs_str = ", ".join(doc_links)
                lines.append(f"| {model} | {docs_str} |")
            lines.append("")

    readme_path = os.path.join(examples_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
