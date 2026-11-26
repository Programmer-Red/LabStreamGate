export enum StreamGateState {
  Invalid,
  Pending,
  Usable,
}

export enum StreamGateFeature {
  Basic = "basic",
  Pingfall = "pingfall",
}

type FeatureSettings = {
  [K in StreamGateFeature]: K extends StreamGateFeature.Basic
  ? Record<string, never>
  : K extends StreamGateFeature.Pingfall
  ? {
    /**
     * The status code that should drop the connection when pingfall is detected
     */
    status: number[];
    /**
     * Whether to drop connection when unknown network error is detected
     */
    drop_unknown: boolean;
  }
  : never;
};

export interface StreamGateOptions {
  /**
   * Website name for local scope
   */
  name: string;
  /**
   * API base URL from local LabStreamGate controller, typically `http://127.0.0.1:3307`
   */
  api: string;
  /**
   * Enabled features
   */
  features: StreamGateFeature[];
  /**
   * Feature settings
   */
  settings?: Partial<FeatureSettings>;
}

export interface StreamGateInstance {
  /**
   * Instance name, will be displayed in local LabStreamGate UI
   */
  label?: string;
  /**
   * Remote WebSocket URL
   */
  remote: string;
  /**
   * Local proxy server addr, use `127.0.0.1:0` to bind to a random port
   */
  local: string;
  /**
   * Instance latency, in milliseconds, -1 means unusable
   */
  latency?: number;
}

export const STREAMGATE_MINIMUM_REQUIRED = "0.4";

export enum StreamGateErrorKind {
  DaemonUnavailable = "daemon_unavailable",
  VersionMismatch = "daemon_version_mismatch",
  DaemonError = "daemon_error",
  ScopeUnverified = "scope_unverified",
  MissingScope = "missing_scope",
}

export class StreamGateError extends Error {
  kind: StreamGateErrorKind;
  constructor(kind: StreamGateErrorKind, message: string) {
    super(message);
    this.name = "StreamGateError";
    this.kind = kind;
  }
}
