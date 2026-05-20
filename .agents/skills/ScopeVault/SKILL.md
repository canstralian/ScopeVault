```markdown
# ScopeVault Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the ScopeVault Python codebase. ScopeVault is a Python project with no detected framework, focusing on clean, maintainable code through consistent naming, import/export styles, and a structured approach to testing. This guide will help you write, organize, and test code in line with the repository's standards.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `user_profile.py`, `data_manager.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .utils import parse_data
    from ..models import User
    ```

### Export Style
- Use **named exports** (explicitly define what is exported).
  - Example:
    ```python
    def calculate_score(data):
        # function body

    class ScoreManager:
        # class body

    __all__ = ["calculate_score", "ScoreManager"]
    ```

### Commit Patterns
- Commit messages are freeform, with no strict prefix requirements.
- Aim for descriptive messages, averaging around 72 characters.
  - Example:
    ```
    Add initial implementation of user authentication logic
    ```

## Workflows

### Adding a New Module
**Trigger:** When you need to add a new feature or logical component.
**Command:** `/add-module`

1. Create a new Python file using snake_case (e.g., `feature_x.py`).
2. Implement your functions/classes.
3. Use relative imports for any internal dependencies.
4. Define `__all__` for named exports.
5. Write corresponding tests in a file matching `*.test.*` pattern.

### Running Tests
**Trigger:** When you want to verify code correctness.
**Command:** `/run-tests`

1. Identify test files (files matching `*.test.*`).
2. Use the project's preferred test runner (framework is unknown; check project docs or use `pytest` as a default).
3. Run tests and review results.

   Example (using pytest):
   ```bash
   pytest
   ```

### Writing Commits
**Trigger:** When saving your work.
**Command:** `/commit`

1. Write a descriptive commit message (around 72 characters).
2. No strict prefix required, but clarity is encouraged.
   - Example: `Fix bug in data parsing for edge case inputs`

## Testing Patterns

- Test files follow the `*.test.*` naming pattern (e.g., `user_profile.test.py`).
- The specific testing framework is not detected; use standard Python test frameworks such as `unittest` or `pytest`.
- Place tests alongside or near the modules they test for easier maintenance.

  Example test file:
  ```python
  # user_profile.test.py
  import unittest
  from .user_profile import UserProfile

  class TestUserProfile(unittest.TestCase):
      def test_creation(self):
          user = UserProfile("Alice")
          self.assertEqual(user.name, "Alice")
  ```

## Commands
| Command       | Purpose                                      |
|---------------|----------------------------------------------|
| /add-module   | Scaffold and add a new module                |
| /run-tests    | Run all test files in the repository         |
| /commit       | Commit changes with a descriptive message    |
```