// Compile-time check of the hand-written WebSocketCommandMap against the server-owned ws contract
// (src/util/generated/wsContract.ts, generated from core/usage). When the server's book changes and the contract is
// regenerated, `pnpm typecheck` fails here with one message per command that no longer agrees, until the map follows.
//
// For every command in the contract:
// - the map must type it;
// - what the client sends must satisfy the server's payload (required members, member types), and it must not send
//   members the server never reads;
// - the client must not read response members the server never sends, and a primitive member it reads must have
//   the type the server sends (nested server models are opaque `object`s in the contract: presence only).
import type { WsContract } from '@/util/generated/wsContract'
import type { WebSocketCommandMap } from '@/util/webSocketCommands'

type Primitive = string | number | boolean | null | undefined

// keyof over every member of a union (plain `keyof (A | B)` is only the common keys).
type AllKeys<T> = T extends object ? keyof T : never

type Extra<Client, Server> = Exclude<AllKeys<Client>, AllKeys<Server>>

type PayloadProblem<C extends keyof WsContract & keyof WebSocketCommandMap> = [
  WebSocketCommandMap[C]['payload'],
] extends [WsContract[C]['payload']]
  ? [Extra<WebSocketCommandMap[C]['payload'], WsContract[C]['payload']>] extends [never]
    ? never
    : `${C}: the payload sends '${Extra<WebSocketCommandMap[C]['payload'], WsContract[C]['payload']> & string}', which the server does not read`
  : `${C}: the payload does not satisfy the server's contract`

type PrimitiveMismatch<Client, Server, C extends string> = {
  [K in keyof Client & keyof Server]: Server[K] extends Primitive
    ? [Server[K]] extends [Client[K]]
      ? never
      : `${C}: response.${K & string} has another type on the server`
    : never
}[keyof Client & keyof Server]

type ResponseProblem<C extends keyof WsContract & keyof WebSocketCommandMap> =
  | ([Extra<WebSocketCommandMap[C]['response'], WsContract[C]['response']>] extends [never]
      ? never
      : `${C}: the client reads response.${Extra<WebSocketCommandMap[C]['response'], WsContract[C]['response']> & string}, which the server never sends`)
  | (WebSocketCommandMap[C]['response'] extends object
      ? WsContract[C]['response'] extends object
        ? PrimitiveMismatch<WebSocketCommandMap[C]['response'], WsContract[C]['response'], C>
        : never
      : never)

type CommandProblem<C extends keyof WsContract> = C extends keyof WebSocketCommandMap
  ? PayloadProblem<C> | ResponseProblem<C>
  : `${C}: missing from WebSocketCommandMap`

export type WsContractProblems = { [C in keyof WsContract]: CommandProblem<C> }[keyof WsContract]

// Each problem is a required key of this record, so the compiler lists them by name ("Type '{}' is missing the
// following properties ...") until there are none.
export const WS_CONTRACT_PROBLEMS: Record<WsContractProblems, never> = {}
