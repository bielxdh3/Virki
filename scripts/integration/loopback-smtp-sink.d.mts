export function assertLoopbackSmtpAddress(host: string, recipient: string, sender: string): void;

export function createLoopbackSmtpSink(options: {
  certificate: Buffer;
  privateKey: Buffer;
  username: string;
  password: string;
  recipient: string;
}): Promise<{
  port: number;
  received: Promise<{ code: string; messageId: string }>;
  observations(): { accepted: number; authenticated: number; upgraded: number };
  close(): Promise<void>;
}>;
