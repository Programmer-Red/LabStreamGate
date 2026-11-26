import { nanoid } from "nanoid";
import {
  STREAMGATE_MINIMUM_REQUIRED,
  StreamGateError,
  StreamGateErrorKind,
  StreamGateFeature,
  StreamGateInstance,
  StreamGateOptions,
  StreamGateState,
} from "./types";
import ky, { HTTPError } from "ky";

/**
 * LabStreamGate browser controller client.
 */
class LabStreamGateClient {
  private options: StreamGateOptions;
  private state: StreamGateState;
  private instances: StreamGateInstance[];
  private onStateChangeCallbacks: Map<string, (state: StreamGateState) => void> =
    new Map();
  private onInstancesChangeCallbacks: Map<
    string,
    (instances: StreamGateInstance[]) => void
  > = new Map();
  private interval: ReturnType<typeof setInterval> | null = null;

  private tickCounter = 0;

  constructor(options: StreamGateOptions) {
    this.options = options;
    this.state = StreamGateState.Invalid;
    this.instances = [];
  }

  public getState(): StreamGateState {
    return this.state;
  }

  private setState(state: StreamGateState): void {
    if (this.state === state) {
      return;
    }
    this.state = state;
    for (const cb of this.onStateChangeCallbacks.values()) {
      cb(state);
    }
  }

  public getOptions(): StreamGateOptions {
    return this.options;
  }

  public setOptions(options: Partial<StreamGateOptions>): void {
    this.options = { ...this.options, ...options };
  }

  private async tick() {
    if (this.interval !== null) {
      clearInterval(this.interval);
    }
    this.interval = setInterval(async () => {
      await this.check();
      if (this.state === StreamGateState.Invalid) {
        this.interval && clearInterval(this.interval);
      } else if (this.state === StreamGateState.Usable) {
        if (this.tickCounter % 5 === 0) {
          await this.sync().catch(() => {});
        }
        this.tickCounter++;
        this.tickCounter %= 5;
      }
    }, 3000);
  }

  public async sync() {
    try {
      const data: StreamGateInstance[] = await ky
        .get(`${this.options.api}/pool`, { retry: 0 })
        .json();
      this.instances = data;
      for (const cb of this.onInstancesChangeCallbacks.values()) {
        cb(data);
      }
    } catch (e) {
      if (e instanceof HTTPError) {
        throw new StreamGateError(
          StreamGateErrorKind.DaemonError,
          await e.response.text(),
        );
      } else {
        throw new StreamGateError(
          StreamGateErrorKind.DaemonError,
          "Failed to sync instances, is LabStreamGate running?",
        );
      }
    }
  }

  public async connect(): Promise<void> {
    await this.checkVersion();
    await this.check();
    if (this.state === StreamGateState.Invalid) {
      try {
        await ky.post(`${this.options.api}/connect`, {
          json: {
            name: this.options.name,
            features: this.options.features,
            settings: this.options.settings,
            host: "IN_HEADER",
            state: "pending",
          },
          retry: 0,
        });
        await this.check();
      } catch (e) {
        this.setState(StreamGateState.Invalid);
        if (e instanceof HTTPError) {
          throw new StreamGateError(
            StreamGateErrorKind.DaemonUnavailable,
            `Failed to connect to LabStreamGate controller: ${await e.response.text()}`,
          );
        }
        throw new StreamGateError(
          StreamGateErrorKind.DaemonUnavailable,
          "Failed to connect to LabStreamGate controller",
        );
      }
    }
    this.tick();
  }

  private async checkVersion() {
    try {
      const raw: string | { version: string } = await ky
        .get(`${this.options.api}/version`, { retry: 0 })
        .json();
      const version = typeof raw === "string" ? raw : raw.version;

      if (version < STREAMGATE_MINIMUM_REQUIRED) {
        this.setState(StreamGateState.Invalid);
        throw new StreamGateError(
          StreamGateErrorKind.VersionMismatch,
          `LabStreamGate version ${version} is lower than required ${STREAMGATE_MINIMUM_REQUIRED}`,
        );
      }
    } catch (e) {
      if (e instanceof StreamGateError) throw e;
      if (e instanceof HTTPError) {
        if (e.response.status === 404) {
          throw new StreamGateError(
            StreamGateErrorKind.VersionMismatch,
            `LabStreamGate version is lower than required ${STREAMGATE_MINIMUM_REQUIRED}`,
          );
        }
        throw new StreamGateError(
          StreamGateErrorKind.DaemonError,
          await e.response.text(),
        );
      }
      throw new StreamGateError(
        StreamGateErrorKind.DaemonUnavailable,
        "Failed to check LabStreamGate version, is LabStreamGate running?",
      );
    }
  }

  private async check(): Promise<void> {
    try {
      const resp = await ky.get(`${this.options.api}/connect`);
      if (resp.status === 202) {
        this.setState(StreamGateState.Usable);
      } else if (resp.status === 201) {
        this.setState(StreamGateState.Pending);
      } else {
        this.setState(StreamGateState.Invalid);
      }
    } catch {
      this.setState(StreamGateState.Invalid);
    }
  }

  public async add(instance: StreamGateInstance): Promise<StreamGateInstance> {
    try {
      for (const i of this.instances) {
        if (i.remote === instance.remote) {
          return i;
        }
      }
      const data: StreamGateInstance = await ky
        .post(`${this.options.api}/pool`, {
          json: instance,
        })
        .json();
      this.instances.push(data);
      for (const cb of this.onInstancesChangeCallbacks.values()) {
        cb(this.instances);
      }
      return data;
    } catch (e) {
      if (e instanceof HTTPError) {
        throw new StreamGateError(
          StreamGateErrorKind.DaemonError,
          await e.response.text(),
        );
      }
      throw new StreamGateError(
        StreamGateErrorKind.DaemonError,
        "Failed to add instance, is LabStreamGate running?",
      );
    }
  }

  public get(local: string): StreamGateInstance | null {
    return this.instances.find((i) => i.local === local) || null;
  }

  public async delete(local: string): Promise<void> {
    try {
      await ky.delete(`${this.options.api}/pool`, {
        json: { local },
      });
      this.instances = this.instances.filter((i) => i.local !== local);
      for (const cb of this.onInstancesChangeCallbacks.values()) {
        cb(this.instances);
      }
    } catch (e) {
      if (e instanceof HTTPError) {
        throw new StreamGateError(
          StreamGateErrorKind.DaemonError,
          await e.response.text(),
        );
      }
      throw new StreamGateError(
        StreamGateErrorKind.DaemonError,
        "Failed to delete instance, is LabStreamGate running?",
      );
    }
  }

  public list(): StreamGateInstance[] {
    return this.instances;
  }

  public onStateChange(fn: (state: StreamGateState) => void): string {
    const id = nanoid();
    this.onStateChangeCallbacks.set(id, fn);
    return id;
  }

  public offStateChange(id: string): void {
    this.onStateChangeCallbacks.delete(id);
  }

  public onInstancesChange(fn: (instances: StreamGateInstance[]) => void): string {
    const id = nanoid();
    this.onInstancesChangeCallbacks.set(id, fn);
    return id;
  }

  public offInstancesChange(id: string): void {
    this.onInstancesChangeCallbacks.delete(id);
  }
}

export {
  LabStreamGateClient,
  LabStreamGateClient as StreamGate,
  StreamGateOptions,
  StreamGateInstance,
  StreamGateState,
  StreamGateFeature,
  StreamGateErrorKind,
  StreamGateError,
};
