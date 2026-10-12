import { useState } from "react";
import { useChangePassword } from "../api/hooks";
import { Button, Field, Modal, useToast } from "./ui";

export function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const change = useChangePassword();
  const toast = useToast();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const mismatch = again !== "" && again !== next;
  return (
    <Modal title="Change your password" onClose={onClose}
      footer={<><Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" loading={change.isPending} disabled={!current || next.length < 10 || next !== again}
          onClick={() => change.mutate({ current_password: current, new_password: next }, { onSuccess: () => { toast.success("Password changed"); onClose(); }, onError: toast.error })}>Change password</Button></>}>
      <div className="form">
        <Field label="Current password"><input className="input" type="password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" autoFocus /></Field>
        <Field label="New password" hint="At least 10 characters."><input className="input" type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" /></Field>
        <Field label="Repeat new password" error={mismatch ? "Passwords do not match" : null}><input className="input" type="password" value={again} onChange={(e) => setAgain(e.target.value)} autoComplete="new-password" /></Field>
      </div>
    </Modal>
  );
}
