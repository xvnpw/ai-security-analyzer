import logging
from pathlib import Path
from typing import Callable

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

logger = logging.getLogger(__name__)


class FabricToolsFilter:
    def __init__(self, included: str = "", excluded: str = ""):
        self.included = self._split_string(included)
        self.excluded = self._split_string(excluded)

    def _split_string(self, input_str: str) -> list[str]:
        if input_str:
            try:
                return [item.strip() for item in input_str.split(",")]
            except (AttributeError, TypeError):
                # Handle cases where input_str is None or not a string
                return []
        else:
            return []

    def get_fabric_tools_list(self, fabric_tools: list[Callable[[str], str]]) -> list[Callable[[str], str]]:
        if self.included:
            included_tools = [tool for tool in fabric_tools if tool.__name__ in self.included]
            return included_tools
        elif self.excluded:
            excluded_tools = [tool for tool in fabric_tools if tool.__name__ not in self.excluded]
            return excluded_tools
        else:
            return fabric_tools


class FabricTools:
    """Manages fabric patterns and their execution"""

    def __init__(
        self,
        llm: BaseChatModel,
        use_system_message: bool = True,
        max_number_of_tools: int = 1000,
        included_tools: str = "",
        excluded_tools: str = "",
    ):
        self.llm = llm
        self.use_system_message = use_system_message
        self.max_number_of_tools = max_number_of_tools
        self.tools_filter = FabricToolsFilter(included_tools, excluded_tools)
        self._patterns_cache: dict[str, str] = {}

    def read_fabric_pattern(self, pattern_name: str) -> str:
        """Read and cache fabric pattern content"""
        if pattern_name in self._patterns_cache:
            return self._patterns_cache[pattern_name]

        root_project_dir = Path(__file__).resolve().parent.parent
        patterns_folder = root_project_dir / "prompts/fabric_patterns"
        file_path = patterns_folder / pattern_name / "system.md"

        logger.debug(f"Reading fabric pattern from: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
            self._patterns_cache[pattern_name] = content
            return content
        except FileNotFoundError:
            logger.error(f"Pattern file not found: {file_path}")
            raise
        except Exception as e:
            logger.error(f"Error reading pattern file: {e}")
            raise

    def invoke_llm(self, input: str, pattern_name: str) -> str:
        """Invoke LLM with proper error handling"""
        try:
            fabric_pattern = self.read_fabric_pattern(pattern_name)

            logger.debug(
                f"Invoking LLM with pattern={pattern_name}, "
                f"system_message={self.use_system_message}, "
                f"input_preview={input[:50]}..."
            )

            message_class = SystemMessage if self.use_system_message else HumanMessage
            messages = [
                message_class(content=fabric_pattern),
                HumanMessage(content=input),
            ]

            response = self.llm.invoke(messages)
            assert isinstance(response.content, str)  # Ensure response is string type

            logger.debug(f"LLM response preview: {response.content[:50]}...")
            return response.content

        except Exception as e:
            logger.error(f"Error invoking LLM: {e}")
            raise

    def agility_story(self, input: str) -> str:
        """Create a user story and acceptance criteria using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "agility_story")

    def ai(self, input: str) -> str:
        """Interpret and answer questions insightfully using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "ai")

    def analyze_answers(self, input: str) -> str:
        """Analyze answers for correctness using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_answers")

    def analyze_candidates(self, input: str) -> str:
        """Analyze and compare two running candidates using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_candidates")

    def analyze_cfp_submission(self, input: str) -> str:
        """Analyze conference session submission abstracts using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_cfp_submission")

    def analyze_claims(self, input: str) -> str:
        """Analyze truth claims and arguments using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_claims")

    def analyze_comments(self, input: str) -> str:
        """Analyze internet comments to characterize their sentiments using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_comments")

    def analyze_debate(self, input: str) -> str:
        """Analyze debate using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_debate")

    def analyze_email_headers(self, input: str) -> str:
        """Analyze email headers for SPF, DKIM, DMARC, and ARC results using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_email_headers")

    def analyze_incident(self, input: str) -> str:
        """Analyze cybersecurity incident articles using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_incident")

    def analyze_interviewer_techniques(self, input: str) -> str:
        """Analyze interviewer techniques using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_interviewer_techniques")

    def analyze_logs(self, input: str) -> str:
        """Analyze log files to identify patterns, anomalies, and potential issues using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_logs")

    def analyze_malware(self, input: str) -> str:
        """Analyze malware using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_malware")

    def analyze_military_strategy(self, input: str) -> str:
        """Analyze military strategy using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_military_strategy")

    def analyze_paper(self, input: str) -> str:
        """Analyze research paper using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_paper")

    def analyze_patent(self, input: str) -> str:
        """Analyze patent using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_patent")

    def analyze_personality(self, input: str) -> str:
        """Perform in-depth psychological analysis on the main person in the input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_personality")

    def analyze_presentation(self, input: str) -> str:
        """Analyze and critique a presentation using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_presentation")

    def analyze_product_feedback(self, input: str) -> str:
        """Analyze product feedback using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_product_feedback")

    def analyze_proposition(self, input: str) -> str:
        """Analyze a federal, state, or local ballot proposition using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_proposition")

    def analyze_prose(self, input: str) -> str:
        """Analyze and evaluate prose using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_prose")

    def analyze_prose_json(self, input: str) -> str:
        """Analyze prose input for novelty, clarity, and prose using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_prose_json")

    def analyze_prose_pinker(self, input: str) -> str:
        """Analyze prose based on Steven Pinker's book, The Sense of Style, using fabric pattern.

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_prose_pinker")

    def analyze_sales_call(self, input: str) -> str:
        """Analyze sales call transcripts using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_sales_call")

    def analyze_spiritual_text(self, input: str) -> str:
        """Analyze spiritual text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_spiritual_text")

    def analyze_tech_impact(self, input: str) -> str:
        """Analyze the impact of technology projects on society using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_tech_impact")

    def analyze_threat_report(self, input: str) -> str:
        """Analyze cybersecurity threat report using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_threat_report")

    def analyze_threat_report_trends(self, input: str) -> str:
        """Analyze threat report trends using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_threat_report_trends")

    def answer_interview_question(self, input: str) -> str:
        """Generate tailored responses to technical interview questions using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "answer_interview_question")

    def ask_secure_by_design_questions(self, input: str) -> str:
        """Create a set of secure by design questions using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "ask_secure_by_design_questions")

    def ask_uncle_duke(self, input: str) -> str:
        """Provide expert advice on software development using Java, Spring Framework, and Maven, following the fabric pattern.

        Args:
            input: input text
        """
        return self.invoke_llm(input, "ask_uncle_duke")

    def capture_thinkers_work(self, input: str) -> str:
        """Capture the work of thinkers using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "capture_thinkers_work")

    def check_agreement(self, input: str) -> str:
        """Analyze contracts and agreements for gotchas using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "check_agreement")

    def clean_text(self, input: str) -> str:
        """Clean input text from broken and malformatted text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "clean_text")

    def coding_master(self, input: str) -> str:
        """Explain coding concepts to beginners using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "coding_master")

    def compare_and_contrast(self, input: str) -> str:
        """Compare and contrast the list of items using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "compare_and_contrast")

    def create_5_sentence_summary(self, input: str) -> str:
        """Create concise summaries of input at various depths using a fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_5_sentence_summary")

    def create_academic_paper(self, input: str) -> str:
        """Create an academic paper using Latex formatting with fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_academic_paper")

    def create_ai_jobs_analysis(self, input: str) -> str:
        """Create AI jobs analysis using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_ai_jobs_analysis")

    def create_aphorisms(self, input: str) -> str:
        """Create a list of aphorisms related to the given topic(s) using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_aphorisms")

    def create_art_prompt(self, input: str) -> str:
        """Create art prompt using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_art_prompt")

    def create_better_frame(self, input: str) -> str:
        """Find better, positive mental frames for seeing the world using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_better_frame")

    def create_coding_project(self, input: str) -> str:
        """Create a coding project using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_coding_project")

    def create_command(self, input: str) -> str:
        """Generate CLI commands using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_command")

    def create_cyber_summary(self, input: str) -> str:
        """Create a cybersecurity summary using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_cyber_summary")

    def create_design_document(self, input: str) -> str:
        """Create a design document for software, cloud, and cybersecurity architecture using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_design_document")

    def create_diy(self, input: str) -> str:
        """Create "Do It Yourself" tutorial patterns using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_diy")

    def create_formal_email(self, input: str) -> str:
        """Create a formal email using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_formal_email")

    def create_git_diff_commit(self, input: str) -> str:
        """Create git diff commit using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_git_diff_commit")

    def create_graph_from_input(self, input: str) -> str:
        """Create progress over time graphs from input data using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_graph_from_input")

    def create_hormozi_offer(self, input: str) -> str:
        """Create business offers using Alex Hormozi's $100M Offers concepts as a fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_hormozi_offer")

    def create_idea_compass(self, input: str) -> str:
        """Create a structured and interconnected system of thoughts and ideas using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_idea_compass")

    def create_investigation_visualization(self, input: str) -> str:
        """Create a visualization of intelligence investigations using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_investigation_visualization")

    def create_keynote(self, input: str) -> str:
        """Create TED-quality keynote presentations from input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_keynote")

    def create_logo(self, input: str) -> str:
        """Create simple, elegant, and impactful company logos using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_logo")

    def create_markmap_visualization(self, input: str) -> str:
        """Create Markmap visualization from input data using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_markmap_visualization")

    def create_mermaid_visualization(self, input: str) -> str:
        """Create a visualization using Mermaid syntax from input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_mermaid_visualization")

    def create_mermaid_visualization_for_github(self, input: str) -> str:
        """Create a Mermaid visualization for GitHub using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_mermaid_visualization_for_github")

    def create_micro_summary(self, input: str) -> str:
        """Create a concise, Markdown formatted summary of input content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_micro_summary")

    def create_network_threat_landscape(self, input: str) -> str:
        """Create a network threat landscape report using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_network_threat_landscape")

    def create_npc(self, input: str) -> str:
        """Create a 5E D&D NPC using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_npc")

    def create_pattern(self, input: str) -> str:
        """Create pattern using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_pattern")

    def create_quiz(self, input: str) -> str:
        """Generate quiz questions from input content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_quiz")

    def create_reading_plan(self, input: str) -> str:
        """Create a reading plan based on the input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_reading_plan")

    def create_recursive_outline(self, input: str) -> str:
        """Create a recursive outline using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_recursive_outline")

    def create_report_finding(self, input: str) -> str:
        """Create a markdown security finding for a cyber security assessment report using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_report_finding")

    def create_rpg_summary(self, input: str) -> str:
        """Create a summary of an RPG session transcript using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_rpg_summary")

    def create_security_update(self, input: str) -> str:
        """Create concise security updates for newsletters using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_security_update")

    def create_show_intro(self, input: str) -> str:
        """Create a compelling and interesting podcast show intro using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_show_intro")

    def create_sigma_rules(self, input: str) -> str:
        """Create Sigma rules from security news publications using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_sigma_rules")

    def create_story_explanation(self, input: str) -> str:
        """Tool description: Explain content in a clear and approachable way using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_story_explanation")

    def create_stride_threat_model(self, input: str) -> str:
        """Create a STRIDE threat model using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_stride_threat_model")

    def create_summary(self, input: str) -> str:
        """Create summary from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_summary")

    def create_tags(self, input: str) -> str:
        """Identify tags from text content for mind mapping tools using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_tags")

    def create_threat_scenarios(self, input: str) -> str:
        """Create threat scenarios using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_threat_scenarios")

    def create_ttrc_graph(self, input: str) -> str:
        """Create a TTR-C graph using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_ttrc_graph")

    def create_ttrc_narrative(self, input: str) -> str:
        """Create a narrative for the Time to Remediate Critical Vulnerabilities metric using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_ttrc_narrative")

    def create_upgrade_pack(self, input: str) -> str:
        """Extract world model and task algorithm updates from input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_upgrade_pack")

    def create_user_story(self, input: str) -> str:
        """Create user stories for new features in complex software programs using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_user_story")

    def create_video_chapters(self, input: str) -> str:
        """Create video chapters with timestamps from transcript using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_video_chapters")

    def create_visualization(self, input: str) -> str:
        """Create a visualization using ASCII art from input concepts using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "create_visualization")

    def dialog_with_socrates(self, input: str) -> str:
        """Engage in a deep, meaningful conversation using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "dialog_with_socrates")

    def explain_code(self, input: str) -> str:
        """Explain code, security output, or configuration text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "explain_code")

    def explain_docs(self, input: str) -> str:
        """Explain documentation using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "explain_docs")

    def explain_math(self, input: str) -> str:
        """Explain mathematical equations or concepts in easy-to-understand terms using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "explain_math")

    def explain_project(self, input: str) -> str:
        """Explain projects and usage using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "explain_project")

    def explain_terms(self, input: str) -> str:
        """Explain terms required to understand a given piece of content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "explain_terms")

    def export_data_as_csv(self, input: str) -> str:
        """Export data structures from input text as CSV using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "export_data_as_csv")

    def extract_algorithm_update_recommendations(self, input: str) -> str:
        """Extract algorithm update recommendations using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_algorithm_update_recommendations")

    def extract_article_wisdom(self, input: str) -> str:
        """Extract surprising, insightful, and interesting information from text content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_article_wisdom")

    def extract_book_ideas(self, input: str) -> str:
        """Extract important ideas from a book using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_book_ideas")

    def extract_book_recommendations(self, input: str) -> str:
        """Extract book recommendations from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_book_recommendations")

    def extract_business_ideas(self, input: str) -> str:
        """Extracts top business ideas from input text and elaborates on them using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_business_ideas")

    def extract_controversial_ideas(self, input: str) -> str:
        """Extract controversial ideas from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_controversial_ideas")

    def extract_core_message(self, input: str) -> str:
        """Extract core message from a text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_core_message")

    def extract_ctf_writeup(self, input: str) -> str:
        """Extract CTF writeup using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_ctf_writeup")

    def extract_extraordinary_claims(self, input: str) -> str:
        """Extract extraordinary claims from conversations using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_extraordinary_claims")

    def extract_ideas(self, input: str) -> str:
        """Extract important ideas from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_ideas")

    def extract_insights(self, input: str) -> str:
        """Extracts surprising and powerful insights from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_insights")

    def extract_insights_dm(self, input: str) -> str:
        """Extract insightful information from input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_insights_dm")

    def extract_instructions(self, input: str) -> str:
        """Extract clear, concise step-by-step instructions from instructional video transcripts using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_instructions")

    def extract_jokes(self, input: str) -> str:
        """Extract jokes from text content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_jokes")

    def extract_latest_video(self, input: str) -> str:
        """Extract the latest video URL from a YouTube RSS feed using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_latest_video")

    def extract_main_idea(self, input: str) -> str:
        """Extract the main idea from the input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_main_idea")

    def extract_most_redeeming_thing(self, input: str) -> str:
        """Extract the most redeeming thing from input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_most_redeeming_thing")

    def extract_patterns(self, input: str) -> str:
        """Extract patterns from input data using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_patterns")

    def extract_poc(self, input: str) -> str:
        """Extract proof of concept URL and command from security/bug bounty report using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_poc")

    def extract_predictions(self, input: str) -> str:
        """Extract predictions from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_predictions")

    def extract_primary_problem(self, input: str) -> str:
        """Extract the primary problem from a text or body of work using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_primary_problem")

    def extract_primary_solution(self, input: str) -> str:
        """Extract primary solution from the input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_primary_solution")

    def extract_product_features(self, input: str) -> str:
        """Extract product features from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_product_features")

    def extract_questions(self, input: str) -> str:
        """Extract questions asked by an interviewer using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_questions")

    def extract_recommendations(self, input: str) -> str:
        """Extract recommendations from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_recommendations")

    def extract_references(self, input: str) -> str:
        """Extract references to art, stories, books, literature, papers, and other sources using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_references")

    def extract_skills(self, input: str) -> str:
        """Extract skills from job description using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_skills")

    def extract_song_meaning(self, input: str) -> str:
        """Extract meaning of a song using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_song_meaning")

    def extract_sponsors(self, input: str) -> str:
        """Extract sponsors from a given transcript using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_sponsors")

    def extract_videoid(self, input: str) -> str:
        """Extract video ID from a URL using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_videoid")

    def extract_wisdom(self, input: str) -> str:
        """Extract surprising, insightful, and interesting information from text content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_wisdom")

    def extract_wisdom_agents(self, input: str) -> str:
        """Extract surprising, insightful, and interesting information from text content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_wisdom_agents")

    def extract_wisdom_dm(self, input: str) -> str:
        """Extract insightful and thought-provoking information from input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_wisdom_dm")

    def extract_wisdom_nometa(self, input: str) -> str:
        """Extract surprising, insightful, and interesting information from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "extract_wisdom_nometa")

    def find_hidden_message(self, input: str) -> str:
        """Find hidden political messages in input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "find_hidden_message")

    def get_wow_per_minute(self, input: str) -> str:
        """Determine the wow-factor of content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "get_wow_per_minute")

    def get_youtube_rss(self, input: str) -> str:
        """Return YouTube channel RSS URL using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "get_youtube_rss")

    def identify_dsrp_distinctions(self, input: str) -> str:
        """Identify and explore key distinctions using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "identify_dsrp_distinctions")

    def identify_dsrp_perspectives(self, input: str) -> str:
        """Identify DSRP perspectives using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "identify_dsrp_perspectives")

    def identify_dsrp_relationships(self, input: str) -> str:
        """Identify DSRP relationships using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "identify_dsrp_relationships")

    def identify_dsrp_systems(self, input: str) -> str:
        """Identify and analyze DSRP systems using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "identify_dsrp_systems")

    def identify_job_stories(self, input: str) -> str:
        """Generate insightful and relevant job stories using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "identify_job_stories")

    def improve_academic_writing(self, input: str) -> str:
        """Refine input text using academic writing style with fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "improve_academic_writing")

    def improve_prompt(self, input: str) -> str:
        """Improve LLM prompt using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "improve_prompt")

    def improve_report_finding(self, input: str) -> str:
        """Improve security finding using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "improve_report_finding")

    def improve_writing(self, input: str) -> str:
        """Improve writing of the input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "improve_writing")

    def label_and_rate(self, input: str) -> str:
        """Label and rate content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "label_and_rate")

    def md_callout(self, input: str) -> str:
        """Fabric pattern tool that creates a markdown callout based on the provided text.

        Args:
            input: input text
        """
        return self.invoke_llm(input, "md_callout")

    def official_pattern_template(self, input: str) -> str:
        """Generate an official pattern template using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "official_pattern_template")

    def prepare_7s_strategy(self, input: str) -> str:
        """Prepare comprehensive briefing document for strategic analysis using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "prepare_7s_strategy")

    def provide_guidance(self, input: str) -> str:
        """Provide guidance using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "provide_guidance")

    def rate_ai_response(self, input: str) -> str:
        """Rate the quality of AI responses compared to ultra-qualified humans using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "rate_ai_response")

    def rate_ai_result(self, input: str) -> str:
        """Rate AI result using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "rate_ai_result")

    def rate_content(self, input: str) -> str:
        """Rate and classify input content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "rate_content")

    def rate_value(self, input: str) -> str:
        """Parse and rate value in content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "rate_value")

    def raw_query(self, input: str) -> str:
        """Process input to yield the best possible result using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "raw_query")

    def recommend_artists(self, input: str) -> str:
        """Recommend artists and schedule using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "recommend_artists")

    def recommend_pipeline_upgrades(self, input: str) -> str:
        """Recommend pipeline upgrades using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "recommend_pipeline_upgrades")

    def recommend_talkpanel_topics(self, input: str) -> str:
        """Recommend talk and panel topics based on a person's interests and ideas using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "recommend_talkpanel_topics")

    def refine_design_document(self, input: str) -> str:
        """Refine design documents using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "refine_design_document")

    def review_design(self, input: str) -> str:
        """Review architectural design using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "review_design")

    def show_fabric_options_markmap(self, input: str) -> str:
        """Show a visual representation of Fabric project using Markmap, utilizing fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "show_fabric_options_markmap")

    def solve_with_cot(self, input: str) -> str:
        """Solve problems with detailed, step-by-step responses using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "solve_with_cot")

    def suggest_pattern(self, input: str) -> str:
        """Suggest appropriate fabric patterns or commands based on user input using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "suggest_pattern")

    def summarize(self, input: str) -> str:
        """Summarize input content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize")

    def summarize_debate(self, input: str) -> str:
        """Summarize debate discussions using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_debate")

    def summarize_git_changes(self, input: str) -> str:
        """Summarize recent Github project changes using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_git_changes")

    def summarize_git_diff(self, input: str) -> str:
        """Summarize changes in a Git diff using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_git_diff")

    def summarize_lecture(self, input: str) -> str:
        """Summarize lecture transcript using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_lecture")

    def summarize_legislation(self, input: str) -> str:
        """Summarize complex political proposals and legislation using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_legislation")

    def summarize_micro(self, input: str) -> str:
        """Summarize input content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_micro")

    def summarize_newsletter(self, input: str) -> str:
        """Summarize input newsletter content using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_newsletter")

    def summarize_paper(self, input: str) -> str:
        """Summarize academic paper using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_paper")

    def summarize_prompt(self, input: str) -> str:
        """Summarize AI chat prompts using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_prompt")

    def summarize_pull_requests(self, input: str) -> str:
        """Summarize pull requests to a coding project using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_pull-requests")

    def summarize_rpg_session(self, input: str) -> str:
        """Summarize in-person RPG session using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_rpg_session")

    def to_flashcards(self, input: str) -> str:
        """Create Anki flashcards from input text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "to_flashcards")

    def transcribe_minutes(self, input: str) -> str:
        """Extract minutes from a transcribed meeting using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "transcribe_minutes")

    def translate(self, input: str) -> str:
        """Translate input text to another language using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "translate")

    def tweet(self, input: str) -> str:
        """Craft engaging tweets with emojis using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "tweet")

    def write_essay(self, input: str) -> str:
        """Write a concise and clear essay on the topic of the input provided using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "write_essay")

    def write_hackerone_report(self, input: str) -> str:
        """Write a bug bounty report using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "write_hackerone_report")

    def write_latex(self, input: str) -> str:
        """Generate syntactically correct LaTeX code for a .tex document using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "write_latex")

    def write_micro_essay(self, input: str) -> str:
        """Write a concise and clear micro essay on the provided topic using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "write_micro_essay")

    def write_nuclei_template_rule(self, input: str) -> str:
        """Write YAML Nuclei templates using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "write_nuclei_template_rule")

    def write_pull_request(self, input: str) -> str:
        """Draft a pull request description using fabric pattern

        Args:
            input: input text representing git diff command output
        """
        return self.invoke_llm(input, "write_pull-request")

    def write_semgrep_rule(self, input: str) -> str:
        """Write a Semgrep rule using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "write_semgrep_rule")

    def find_logical_fallacies(self, input: str) -> str:
        """Tool to identify logical fallacies in text using fabric pattern

        Args:
            input: input text
        """
        return self.invoke_llm(input, "find_logical_fallacies")

    def analyze_mistakes(self, input: str) -> str:
        """Tool to analyze thinking patterns and anticipate mistakes, using a fabric pattern approach.

        Args:
            input: input text
        """
        return self.invoke_llm(input, "analyze_mistakes")

    def summarize_meeting(self, input: str) -> str:
        """Tool for summarizing meeting transcripts into key sections in a structured format. This is a fabric pattern.

        Args:
            input: input text
        """
        return self.invoke_llm(input, "summarize_meeting")

    def get_fabric_tools(self) -> list[Callable[[str], str]]:
        filtered_tools = self.tools_filter.get_fabric_tools_list(self._get_fabric_tools())
        if len(filtered_tools) > self.max_number_of_tools:
            raise ValueError(
                f"Model supporting only {self.max_number_of_tools} tools, but got {len(filtered_tools)}. Use --fabric-patterns-include/--fabric-patterns-exclude or different model."
            )
        return filtered_tools

    def _get_fabric_tools(self) -> list[Callable[[str], str]]:
        return [
            self.agility_story,
            self.ai,
            self.analyze_answers,
            self.analyze_candidates,
            self.analyze_cfp_submission,
            self.analyze_claims,
            self.analyze_comments,
            self.analyze_debate,
            self.analyze_email_headers,
            self.analyze_incident,
            self.analyze_interviewer_techniques,
            self.analyze_logs,
            self.analyze_malware,
            self.analyze_military_strategy,
            self.analyze_paper,
            self.analyze_patent,
            self.analyze_personality,
            self.analyze_presentation,
            self.analyze_product_feedback,
            self.analyze_proposition,
            self.analyze_prose,
            self.analyze_prose_json,
            self.analyze_prose_pinker,
            self.analyze_sales_call,
            self.analyze_spiritual_text,
            self.analyze_tech_impact,
            self.analyze_threat_report,
            self.analyze_threat_report_trends,
            self.answer_interview_question,
            self.ask_secure_by_design_questions,
            self.ask_uncle_duke,
            self.capture_thinkers_work,
            self.check_agreement,
            self.clean_text,
            self.coding_master,
            self.compare_and_contrast,
            self.create_5_sentence_summary,
            self.create_academic_paper,
            self.create_ai_jobs_analysis,
            self.create_aphorisms,
            self.create_art_prompt,
            self.create_better_frame,
            self.create_coding_project,
            self.create_command,
            self.create_cyber_summary,
            self.create_design_document,
            self.create_diy,
            self.create_formal_email,
            self.create_git_diff_commit,
            self.create_graph_from_input,
            self.create_hormozi_offer,
            self.create_idea_compass,
            self.create_investigation_visualization,
            self.create_keynote,
            self.create_logo,
            self.create_markmap_visualization,
            self.create_mermaid_visualization,
            self.create_mermaid_visualization_for_github,
            self.create_micro_summary,
            self.create_network_threat_landscape,
            self.create_npc,
            self.create_pattern,
            self.create_quiz,
            self.create_reading_plan,
            self.create_recursive_outline,
            self.create_report_finding,
            self.create_rpg_summary,
            self.create_security_update,
            self.create_show_intro,
            self.create_sigma_rules,
            self.create_story_explanation,
            self.create_stride_threat_model,
            self.create_summary,
            self.create_tags,
            self.create_threat_scenarios,
            self.create_ttrc_graph,
            self.create_ttrc_narrative,
            self.create_upgrade_pack,
            self.create_user_story,
            self.create_video_chapters,
            self.create_visualization,
            self.dialog_with_socrates,
            self.explain_code,
            self.explain_docs,
            self.explain_math,
            self.explain_project,
            self.explain_terms,
            self.export_data_as_csv,
            self.extract_algorithm_update_recommendations,
            self.extract_article_wisdom,
            self.extract_book_ideas,
            self.extract_book_recommendations,
            self.extract_business_ideas,
            self.extract_controversial_ideas,
            self.extract_core_message,
            self.extract_ctf_writeup,
            self.extract_extraordinary_claims,
            self.extract_ideas,
            self.extract_insights,
            self.extract_insights_dm,
            self.extract_instructions,
            self.extract_jokes,
            self.extract_latest_video,
            self.extract_main_idea,
            self.extract_most_redeeming_thing,
            self.extract_patterns,
            self.extract_poc,
            self.extract_predictions,
            self.extract_primary_problem,
            self.extract_primary_solution,
            self.extract_product_features,
            self.extract_questions,
            self.extract_recommendations,
            self.extract_references,
            self.extract_skills,
            self.extract_song_meaning,
            self.extract_sponsors,
            self.extract_videoid,
            self.extract_wisdom,
            self.extract_wisdom_agents,
            self.extract_wisdom_dm,
            self.extract_wisdom_nometa,
            self.find_hidden_message,
            self.get_wow_per_minute,
            self.get_youtube_rss,
            self.identify_dsrp_distinctions,
            self.identify_dsrp_perspectives,
            self.identify_dsrp_relationships,
            self.identify_dsrp_systems,
            self.identify_job_stories,
            self.improve_academic_writing,
            self.improve_prompt,
            self.improve_report_finding,
            self.improve_writing,
            self.label_and_rate,
            self.md_callout,
            self.official_pattern_template,
            self.prepare_7s_strategy,
            self.provide_guidance,
            self.rate_ai_response,
            self.rate_ai_result,
            self.rate_content,
            self.rate_value,
            self.raw_query,
            self.recommend_artists,
            self.recommend_pipeline_upgrades,
            self.recommend_talkpanel_topics,
            self.refine_design_document,
            self.review_design,
            self.show_fabric_options_markmap,
            self.solve_with_cot,
            self.suggest_pattern,
            self.summarize,
            self.summarize_debate,
            self.summarize_git_changes,
            self.summarize_git_diff,
            self.summarize_lecture,
            self.summarize_legislation,
            self.summarize_micro,
            self.summarize_newsletter,
            self.summarize_paper,
            self.summarize_prompt,
            self.summarize_pull_requests,
            self.summarize_rpg_session,
            self.to_flashcards,
            self.transcribe_minutes,
            self.translate,
            self.tweet,
            self.write_essay,
            self.write_hackerone_report,
            self.write_latex,
            self.write_micro_essay,
            self.write_nuclei_template_rule,
            self.write_pull_request,
            self.write_semgrep_rule,
            self.find_logical_fallacies,
            self.analyze_mistakes,
            self.summarize_meeting,
        ]
