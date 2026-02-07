"""
Tests for the core Skill model.
"""

import pytest
from skillguard.core.skill import Skill, SkillManifest, SkillCode, SkillCorpus
from skillguard.taxonomy import SkillCategory, ProgrammingLanguage


class TestSkillManifest:
    """Tests for SkillManifest parsing."""
    
    def test_parse_basic_markdown(self):
        content = '''# My Skill

## Description
A test skill that does things.

## Capabilities
- Capability 1
- Capability 2

## Permissions
- Permission 1
'''
        manifest = SkillManifest.from_markdown(content)
        
        assert manifest.name == "My Skill"
        assert "test skill" in manifest.description.lower()
        assert len(manifest.declared_capabilities) == 2
        assert len(manifest.declared_permissions) == 1
    
    def test_empty_manifest(self):
        content = ""
        manifest = SkillManifest.from_markdown(content)
        
        assert manifest.name == "Unknown Skill"


class TestSkillCode:
    """Tests for SkillCode model."""
    
    def test_language_detection(self, tmp_path):
        py_file = tmp_path / "test.py"
        py_file.write_text("def hello(): pass")
        
        code = SkillCode.from_file(py_file)
        
        assert code.language == ProgrammingLanguage.PYTHON
        assert code.line_count == 1
        assert code.content_hash != ""
    
    def test_hash_uniqueness(self):
        code1 = SkillCode(filename="a.py", language=ProgrammingLanguage.PYTHON, content="print('a')")
        code2 = SkillCode(filename="b.py", language=ProgrammingLanguage.PYTHON, content="print('b')")
        
        assert code1.content_hash != code2.content_hash


class TestSkill:
    """Tests for Skill model."""
    
    def test_from_components(self):
        skill = Skill.from_components(
            manifest_content="# Test\nA test skill.",
            code_content="def test(): pass",
            code_filename="test.py"
        )
        
        assert skill.manifest.name == "Test"
        assert skill.code.language == ProgrammingLanguage.PYTHON
        assert skill.id != ""
    
    def test_unique_id(self):
        skill1 = Skill.from_components("# A\nSkill A", "code1")
        skill2 = Skill.from_components("# B\nSkill B", "code2")
        
        assert skill1.id != skill2.id
    
    def test_full_context(self):
        skill = Skill.from_components("# Test\nDesc", "def x(): pass")
        context = skill.get_full_context()
        
        assert "SKILL MANIFEST" in context
        assert "SKILL CODE" in context


class TestSkillCorpus:
    """Tests for SkillCorpus."""
    
    def test_add_skill(self):
        corpus = SkillCorpus()
        skill = Skill.from_components("# Test", "code")
        
        corpus.add_skill(skill)
        
        assert len(corpus.skills) == 1
    
    def test_no_duplicates(self):
        corpus = SkillCorpus()
        skill = Skill.from_components("# Test", "code")
        
        corpus.add_skill(skill)
        corpus.add_skill(skill)  # Same skill
        
        assert len(corpus.skills) == 1
    
    def test_statistics(self):
        corpus = SkillCorpus()
        corpus.add_skill(Skill.from_components("# A", "code1"))
        corpus.add_skill(Skill.from_components("# B", "code2"))
        
        stats = corpus.get_statistics()
        
        assert stats["total_skills"] == 2
        assert "languages" in stats
        assert "categories" in stats
