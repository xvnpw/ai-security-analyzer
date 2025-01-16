import sqlite3
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.checkpoint.base import BaseCheckpointSaver
from pathlib import Path
import logging
from ai_security_analyzer.config import AppConfig
from langchain_core.runnables.config import RunnableConfig

logger = logging.getLogger(__name__)


class CheckpointManager:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.checkpoint_dir = Path(config.checkpoint_dir)
        self.checkpoint_dir.mkdir(exist_ok=True)
        self.db_path = self.checkpoint_dir / "checkpoints.sqlite"
        if config.clear_checkpoints:
            self.clear_checkpoints()
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.saver = SqliteSaver(self.conn)

    def check_resume(self) -> None:
        thread_id = self.get_thread_id()
        checkpoint_config = RunnableConfig(
            configurable={"thread_id": thread_id},
        )

        if self.config.resume:
            checkpoint = self.saver.get(checkpoint_config)
            if checkpoint:
                logger.info(f"Resumed execution from checkpoint: {thread_id}")
            else:
                logger.warning(f"Could not resume from checkpoint: {thread_id}")
        else:
            checkpoint = self.saver.get(checkpoint_config)
            if checkpoint:
                self.clear_checkpoint(thread_id)
                logger.debug(f"Cleared checkpoint: {thread_id}")

    def get_thread_id(self) -> str:
        """Generate a unique execution ID based on input parameters"""
        return f"{self.config.mode}_{self.config.target}_{self.config.agent_prompt_type}"

    def get_checkpointer(self) -> BaseCheckpointSaver[str]:
        return self.saver

    def clear_checkpoints(self) -> None:
        if self.db_path.exists():
            self.db_path.unlink()

    def clear_current_checkpoint(self) -> None:
        thread_id = self.get_thread_id()
        self.clear_checkpoint(thread_id)

    def clear_checkpoint(self, thread_id: str) -> None:
        try:
            self.conn.execute("DELETE FROM checkpoints WHERE thread_id = ?", (thread_id,))
            self.conn.execute("DELETE FROM writes WHERE thread_id = ?", (thread_id,))
            self.conn.commit()
        except sqlite3.Error as e:
            self.conn.rollback()  # Rollback in case of error
            raise RuntimeError(f"Failed to clear checkpoint: {str(e)}")

    def close(self) -> None:
        """Explicitly close the database connection."""
        if hasattr(self, "conn"):
            self.conn.close()

    def __enter__(self) -> "CheckpointManager":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:  # type: ignore[no-untyped-def]
        self.close()

    def __del__(self) -> None:
        self.close()
