import { mkdir, appendFile } from 'node:fs/promises';
import { dirname } from 'node:path';

export class AuditLog {
  constructor(path) {
    this.path = path;
  }

  async write(event) {
    await mkdir(dirname(this.path), { recursive: true });
    const record = {
      timestamp: new Date().toISOString(),
      ...event
    };
    await appendFile(this.path, `${JSON.stringify(record)}\n`, 'utf8');
  }
}
