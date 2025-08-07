import DOMPurify from 'dompurify';

/**
 * Secure text sanitization utilities using DOMPurify
 * Protects against XSS, HTML injection, and other attacks
 */

/**
 * Sanitize text to plain text only (removes all HTML)
 * Use for displaying user names, titles, etc.
 */
export const sanitizeText = (text) => {
  if (!text || typeof text !== 'string') return '';
  
  // Use DOMPurify to strip all HTML and return plain text
  const clean = DOMPurify.sanitize(text, { 
    ALLOWED_TAGS: [],           // No HTML tags allowed
    ALLOWED_ATTR: [],           // No HTML attributes allowed
    KEEP_CONTENT: true,         // Keep text content
    ALLOW_DATA_ATTR: false,     // No data-* attributes
    ALLOW_UNKNOWN_PROTOCOLS: false,  // Block javascript:, data:, etc.
  });
  
  return clean.trim();
};

/**
 * Sanitize HTML content (allows safe HTML tags)
 * Use for rich text content, descriptions, etc.
 */
export const sanitizeHTML = (html) => {
  if (!html || typeof html !== 'string') return '';
  
  // Allow only safe HTML tags and attributes
  const clean = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['p', 'br', 'strong', 'em', 'u', 'i', 'b', 'span'],
    ALLOWED_ATTR: ['class'],
    KEEP_CONTENT: true,
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    FORCE_BODY: false,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    RETURN_TRUSTED_TYPE: false,
  });
  
  return clean;
};

/**
 * Validate and sanitize email addresses
 */
export const sanitizeEmail = (email) => {
  if (!email || typeof email !== 'string') return '';
  
  // First sanitize as text
  const cleanEmail = sanitizeText(email);
  
  // Basic email validation (server should do comprehensive validation)
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  return emailRegex.test(cleanEmail) ? cleanEmail : '';
};

/**
 * Sanitize URLs to prevent javascript:, data:, and other dangerous protocols
 */
export const sanitizeURL = (url) => {
  if (!url || typeof url !== 'string') return '';
  
  try {
    const urlObj = new URL(url);
    
    // Only allow safe protocols
    const safeProtocols = ['http:', 'https:', 'mailto:'];
    
    if (safeProtocols.includes(urlObj.protocol)) {
      return url;
    }
    
    return '';
  } catch {
    return '';
  }
};

/**
 * Deep sanitize user object with multiple fields
 */
export const sanitizeUserData = (userData) => {
  if (!userData || typeof userData !== 'object') return null;
  
  return {
    id: userData.id, // Numeric ID should be safe, but validate on backend
    name: sanitizeText(userData.name),
    email: sanitizeEmail(userData.email),
    picture: sanitizeURL(userData.picture),
    // Add other fields as needed with appropriate sanitization
  };
};
