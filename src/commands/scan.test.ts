import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../scanner/tls.js', () => ({
  scanHost: vi.fn().mockRejectedValue(new Error('should not be called')),
}));

vi.mock('../scanner/classifier.js', () => ({
  classify: vi.fn(),
}));

vi.mock('../scanner/grader.js', () => ({
  grade: vi.fn(),
  shouldFailForGrade: vi.fn().mockReturnValue(false),
}));

import { scanCommand } from './scan.js';
import { scanHost } from '../scanner/tls.js';

describe('scanCommand input validation', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('rejects hostname with shell metacharacters', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await scanCommand(['example.com;rm -rf /'], {
      format: 'terminal',
      timeout: 5000,
      verbose: false,
      failGrade: 'C',
    });
    expect(code).toBe(1);
    expect(scanHost).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('rejects hostname with null bytes', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await scanCommand(['example.com\x00evil'], {
      format: 'terminal',
      timeout: 5000,
      verbose: false,
      failGrade: 'C',
    });
    expect(code).toBe(1);
    expect(scanHost).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });

  it('rejects port out of range', async () => {
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const code = await scanCommand(['example.com:99999'], {
      format: 'terminal',
      timeout: 5000,
      verbose: false,
      failGrade: 'C',
    });
    expect(code).toBe(1);
    expect(scanHost).not.toHaveBeenCalled();
    consoleSpy.mockRestore();
  });
});
