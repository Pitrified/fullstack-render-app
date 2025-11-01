# Documentation Requirements

## Task List Documentation Rule

**MANDATORY**: Every task list must end with a documentation update task.

When creating or updating task lists for any feature, spec, or development work, the final task must always be:

```
- [ ] Update project documentation to reflect changes
  - Update README.md with new features/changes
  - Update relevant technical documentation
  - Update API documentation if backend changes were made
  - Update security documentation if security-related changes were made
  - Ensure all new functionality is properly documented
```

## Documentation Standards

### README.md Updates
- Keep the main README current with latest features
- Update setup instructions if dependencies change
- Document new environment variables or configuration
- Update deployment instructions if process changes

### Technical Documentation
- Document new security features in `vulnerabilities.md`
- Update architecture diagrams or descriptions for structural changes
- Document new API endpoints or changes to existing ones
- Update configuration examples and environment templates

### Code Documentation
- Add inline comments for complex security logic
- Document new utility functions and their security implications
- Update docstrings for new or modified functions
- Ensure test documentation explains security test scenarios

## Documentation Maintenance
- Documentation updates are not optional - they are part of feature completion
- Outdated documentation is a security risk and user experience problem
- All documentation should be written for both developers and security auditors
- Keep documentation concise but comprehensive

This rule ensures that the project documentation stays current and accurate, which is critical for security auditing and developer onboarding.