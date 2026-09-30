"""group_soc.stories — turn timelines into readable security stories."""

from .generator import StoryGenerator
from .formatter import format_story

__all__ = ["StoryGenerator", "format_story"]
