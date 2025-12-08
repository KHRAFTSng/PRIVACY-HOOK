"use client";

import { useCallback, useMemo, useState } from "react";
import { FheTypes } from "@cofhe/sdk";
import { AddressInput, IntegerInput, IntegerVariant } from "~~/components/scaffold-eth";
import { useScaffoldReadContract, useScaffoldWriteContract } from "~~/hooks/scaffold-eth";
import { notification } from "~~/utils/scaffold-eth";
import { useEncryptInput } from "../useEncryptInput";

const ZERO_ADDR = "0x0000000000000000000000000000000000000000";

export default function PrivacyPage() {
  const [amount0, setAmount0] = useState<string>("");
  const [amount1, setAmount1] = useState<string>("");
  const [intentAmount, setIntentAmount] = useState<string>("");
  const [intentDir, setIntentDir] = useState<"zeroForOne" | "oneForZero">("zeroForOne");
  const [maker, setMaker] = useState<string>("");
  const [taker, setTaker] = useState<string>("");
  const [matchAmount, setMatchAmount] = useState<string>("");

  const hookAddress = useMemo(() => process.env.NEXT_PUBLIC_PRIVACY_HOOK_ADDRESS || ZERO_ADDR, []);
  const token0Address = useMemo(() => process.env.NEXT_PUBLIC_PRIVACY_TOKEN0_ADDRESS || ZERO_ADDR, []);
  const token1Address = useMemo(() => process.env.NEXT_PUBLIC_PRIVACY_TOKEN1_ADDRESS || ZERO_ADDR, []);

  const { onEncryptInput, isEncryptingInput } = useEncryptInput();
  const { writeContractAsync: writeHook, isPending: isHookPending } = useScaffoldWriteContract({ contractName: "PrivacyHook" });

  const { data: makerIntentActive } = useScaffoldReadContract({
    contractName: "PrivacyHook",
    functionName: "isIntentActive",
    args: [maker || ZERO_ADDR],
  });

  const pending = isHookPending || isEncryptingInput;

  const handleDeposit0 = useCallback(async () => {
    if (!amount0) return;
    await writeHook({ functionName: "depositToken0", args: [BigInt(amount0)] });
    notification.success("Deposited token0");
  }, [amount0, writeHook]);

  const handleDeposit1 = useCallback(async () => {
    if (!amount1) return;
    await writeHook({ functionName: "depositToken1", args: [BigInt(amount1)] });
    notification.success("Deposited token1");
  }, [amount1, writeHook]);

  const handleSubmitIntent = useCallback(async () => {
    if (!intentAmount) return;
    const encAmount = await onEncryptInput(FheTypes.Uint128, intentAmount);
    const encDir = await onEncryptInput(FheTypes.Bool, intentDir === "zeroForOne" ? "1" : "0");
    await writeHook({ functionName: "submitIntent", args: [encAmount, encDir] });
    notification.success("Intent submitted");
  }, [intentAmount, intentDir, onEncryptInput, writeHook]);

  const handleSettle = useCallback(async () => {
    if (!maker || !taker || !matchAmount) return;
    const encAmt = await onEncryptInput(FheTypes.Uint128, matchAmount);
    await writeHook({ functionName: "settleMatched", args: [maker, taker, encAmt] });
    notification.success("Matched settlement sent");
  }, [maker, taker, matchAmount, onEncryptInput, writeHook]);

  return (
    <div className="flex flex-col gap-6">
      <h1 className="text-2xl font-bold">Privacy Hook Control</h1>
      <div className="text-sm text-base-content/70">
        Using hook at <span className="font-mono">{hookAddress}</span>
        <br />
        Token0: <span className="font-mono">{token0Address}</span>
        <br />
        Token1: <span className="font-mono">{token1Address}</span>
      </div>

      <section className="card bg-base-100 shadow p-4 gap-3">
        <h2 className="text-lg font-semibold">Deposit (wrap into encrypted balance)</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="flex gap-2 items-end">
            <IntegerInput value={amount0} onChange={setAmount0} variant={IntegerVariant.UINT128} />
            <button className={`btn btn-primary ${pending ? "btn-disabled" : ""}`} onClick={handleDeposit0}>
              {pending && <span className="loading loading-spinner loading-xs" />}
              Deposit Token0
            </button>
          </div>
          <div className="flex gap-2 items-end">
            <IntegerInput value={amount1} onChange={setAmount1} variant={IntegerVariant.UINT128} />
            <button className={`btn btn-primary ${pending ? "btn-disabled" : ""}`} onClick={handleDeposit1}>
              {pending && <span className="loading loading-spinner loading-xs" />}
              Deposit Token1
            </button>
          </div>
        </div>
      </section>

      <section className="card bg-base-100 shadow p-4 gap-3">
        <h2 className="text-lg font-semibold">Submit Intent</h2>
        <div className="flex flex-col gap-3">
          <div className="flex gap-2 items-end">
            <IntegerInput value={intentAmount} onChange={setIntentAmount} variant={IntegerVariant.UINT128} />
            <select className="select select-bordered w-40" value={intentDir} onChange={e => setIntentDir(e.target.value as "zeroForOne" | "oneForZero")}>
              <option value="zeroForOne">zeroForOne (token0 → token1)</option>
              <option value="oneForZero">oneForZero (token1 → token0)</option>
            </select>
            <button className={`btn btn-primary ${pending ? "btn-disabled" : ""}`} onClick={handleSubmitIntent}>
              {pending && <span className="loading loading-spinner loading-xs" />}
              Submit Intent
            </button>
          </div>
          <div className="text-sm text-base-content/70">Intent active for maker? {maker ? (makerIntentActive ? "yes" : "no") : "set maker address below"}</div>
        </div>
      </section>

      <section className="card bg-base-100 shadow p-4 gap-3">
        <h2 className="text-lg font-semibold">Relayer Settlement</h2>
        <div className="flex flex-col gap-3">
          <AddressInput value={maker} onChange={setMaker} placeholder="Maker address" />
          <AddressInput value={taker} onChange={setTaker} placeholder="Taker address" />
          <div className="flex gap-2 items-end">
            <IntegerInput value={matchAmount} onChange={setMatchAmount} variant={IntegerVariant.UINT128} />
            <button className={`btn btn-secondary ${pending ? "btn-disabled" : ""}`} onClick={handleSettle}>
              {pending && <span className="loading loading-spinner loading-xs" />}
              Settle Matched
            </button>
          </div>
        </div>
        <p className="text-sm text-base-content/60">Use relayer account to call settleMatched with encrypted amount.</p>
      </section>
    </div>
  );
}

