import { describe, it, expect } from 'vitest';
import { validateHostname, validatePort, validateFilePath } from './validate.js';

describe('validateHostname', () => {
  it('accepts simple hostname', () => {
    expect(validateHostname('example.com')).toBe(true);
  });

  it('accepts hostname with hyphens', () => {
    expect(validateHostname('my-site.example.com')).toBe(true);
  });

  it('accepts IPv4', () => {
    expect(validateHostname('192.168.1.1')).toBe(true);
  });

  it('accepts IPv6', () => {
    expect(validateHostname('::1')).toBe(true);
  });

  it('accepts bracketed IPv6', () => {
    expect(validateHostname('[::1]')).toBe(true);
  });

  it('rejects null bytes', () => {
    expect(validateHostname('example\0.com')).toBe(false);
  });

  it('rejects semicolon', () => {
    expect(validateHostname('example.com;rm -rf /')).toBe(false);
  });

  it('rejects backtick', () => {
    expect(validateHostname('`whoami`')).toBe(false);
  });

  it('rejects dollar sign', () => {
    expect(validateHostname('$HOME')).toBe(false);
  });

  it('rejects pipe', () => {
    expect(validateHostname('example.com|cat /etc/passwd')).toBe(false);
  });

  it('rejects ampersand', () => {
    expect(validateHostname('example.com&bg')).toBe(false);
  });

  it('rejects whitespace', () => {
    expect(validateHostname('example .com')).toBe(false);
    expect(validateHostname('example\t.com')).toBe(false);
  });

  it('rejects hostnames longer than 253 characters', () => {
    const long = 'a'.repeat(254);
    expect(validateHostname(long)).toBe(false);
  });

  it('accepts hostname at exactly 253 characters', () => {
    const exact = 'a'.repeat(253);
    expect(validateHostname(exact)).toBe(true);
  });

  it('rejects empty string', () => {
    expect(validateHostname('')).toBe(false);
  });
});

describe('validatePort', () => {
  it('accepts 443', () => {
    expect(validatePort(443)).toBe(true);
  });

  it('accepts 1', () => {
    expect(validatePort(1)).toBe(true);
  });

  it('accepts 65535', () => {
    expect(validatePort(65535)).toBe(true);
  });

  it('rejects 0', () => {
    expect(validatePort(0)).toBe(false);
  });

  it('rejects 65536', () => {
    expect(validatePort(65536)).toBe(false);
  });

  it('rejects -1', () => {
    expect(validatePort(-1)).toBe(false);
  });

  it('rejects 443.5', () => {
    expect(validatePort(443.5)).toBe(false);
  });

  it('rejects NaN', () => {
    expect(validatePort(NaN)).toBe(false);
  });
});

describe('validateFilePath', () => {
  it('accepts normal absolute path', () => {
    expect(validateFilePath('/home/user/hosts.txt')).toBe(true);
  });

  it('accepts relative path', () => {
    expect(validateFilePath('./hosts.txt')).toBe(true);
  });

  it('rejects null bytes', () => {
    expect(validateFilePath('/home/user/\0hosts.txt')).toBe(false);
  });

  it('rejects empty string', () => {
    expect(validateFilePath('')).toBe(false);
  });
});
