# Product Overview

This is a **secure fullstack Google OAuth authentication application** demonstrating enterprise-grade security practices.

## Core Purpose
- Showcase secure authentication patterns with Google OAuth 2.0
- Implement OWASP Top 10 security protections
- Provide a production-ready template for secure web applications

## Key Features
- **Secure Authentication**: httpOnly cookies, CSRF protection, XSS prevention
- **Session Management**: Server-side sessions with automatic cleanup
- **Security Hardening**: Rate limiting, input sanitization, security headers
- **Production Ready**: Configured for Render.com deployment with PostgreSQL

## Security Focus
This application prioritizes security over features. Every implementation decision considers:
- XSS prevention through DOMPurify sanitization
- CSRF protection via double-submit cookie pattern
- Secure token storage (no localStorage usage)
- Comprehensive logging and monitoring
- Rate limiting on authentication endpoints

## Target Audience
- Developers learning secure authentication patterns
- Teams needing a secure OAuth implementation template
- Security-conscious applications requiring enterprise-grade protection