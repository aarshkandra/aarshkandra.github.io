import type { ErrorCode } from "@aarsh/protocol";

export class AppError extends Error {
  constructor(public readonly status: number, public readonly code: ErrorCode, message?: string, public readonly extra?: Record<string, unknown>) {
    super(message ?? code);
  }
}
export const accessDenied = () => new AppError(401, "ACCESS_DENIED", "Access denied");
export const notFound = () => new AppError(404, "NOT_FOUND", "Not found");
