/* eslint-disable @typescript-eslint/no-explicit-any */
import { Connection, Server } from "partyserver";
import { AuthenticatedServer, Constructor } from "./types.js";

type withOwnershipClassAllowed<Env> = Server<Env> &
  AuthenticatedServer & {
    ctx: {
      storage: {
        get<T = unknown>(key: string, options?: any): Promise<T | undefined>;
        put<T>(key: string, value: T, options?: any): Promise<void>;
      };
    };
  };

/**
 * Mixin to add ownership functionality to an Authenticated and DurableObject server.
 *
 * The setOwner method should be called when the object is created.
 *
 * Every time a connection or request is made, the ownership is checked.
 *
 * @param Base - The base class to extend from.
 *
 * @returns - A new class that extends the base class with ownership functionality.
 */
export const WithOwnership = <
  Env,
  TBase extends Constructor<withOwnershipClassAllowed<Env>>,
>(
  Base: TBase,
) => {
  return class WithOwnership extends Base {
    /**
     * Checks if the current user in the connection or request
     * is the actual owner of the chat.
     *
     * Note that the owner is set when the chat is created.
     *
     * @returns - A boolean indicating if the current user is the owner.
     */
    async #isCurrentUserOwner(): Promise<boolean> {
      const userInfo = this.getClaims();
      const agentStorage = this.ctx.storage;
      const objectOwner = await agentStorage.get("owner");
      if (objectOwner !== userInfo?.sub) {
        return false;
      }
      return true;
    }

    async onAuthenticatedConnect(
      connection: Connection,
      ctx: any,
    ): Promise<void> {
      await super.onAuthenticatedConnect(connection, ctx);
      if (!(await this.#isCurrentUserOwner())) {
        connection.close(1008, "This chat is not yours.");
      }
    }

    async onAuthenticatedRequest(request: Request): Promise<void | Response> {
      await super.onAuthenticatedRequest(request);
      if (!(await this.#isCurrentUserOwner())) {
        return new Response("This chat is not yours.", { status: 403 });
      }
    }

    async setOwner(owner: string, overwrite: boolean = false): Promise<void> {
      if (!owner) {
        throw new Error("Owner cannot be empty");
      }
      const currentOwner = await this.getOwner();
      if (currentOwner && currentOwner !== owner && !overwrite) {
        throw new Error("The owner is already set to another user");
      }
      await this.ctx.storage.put("owner", owner);
    }

    async getOwner(): Promise<string | undefined> {
      return this.ctx.storage.get("owner");
    }
  };
};
