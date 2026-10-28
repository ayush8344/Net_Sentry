"use client";

import type { FlowFeatures } from "@/lib/types";

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[11px] text-muted-dim">{label}</span>
      {children}
    </label>
  );
}

const inputClass =
  "w-full rounded-lg border border-border bg-surface-raised px-2.5 py-1.5 text-sm text-foreground outline-none focus:border-accent/60 focus:ring-1 focus:ring-accent/40 mono";

export default function FlowForm({
  flow,
  onChange,
}: {
  flow: FlowFeatures;
  onChange: (flow: FlowFeatures) => void;
}) {
  const set = <K extends keyof FlowFeatures>(key: K, value: FlowFeatures[K]) =>
    onChange({ ...flow, [key]: value });

  const num = (key: keyof FlowFeatures) => ({
    className: inputClass,
    type: "number",
    value: flow[key] as number,
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => set(key, Number(e.target.value) as never),
  });

  return (
    <div className="space-y-5">
      <div>
        <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-dim">Identity</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Source IP">
            <input className={inputClass} value={flow.source_ip} onChange={(e) => set("source_ip", e.target.value)} />
          </Field>
          <Field label="Destination IP">
            <input className={inputClass} value={flow.destination_ip} onChange={(e) => set("destination_ip", e.target.value)} />
          </Field>
          <Field label="Protocol">
            <select
              className={inputClass}
              value={flow.protocol}
              onChange={(e) => set("protocol", e.target.value as FlowFeatures["protocol"])}
            >
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </Field>
          <Field label="Destination port">
            <input {...num("dst_port")} min={0} max={65535} />
          </Field>
          <Field label="Source port">
            <input {...num("src_port")} min={0} max={65535} />
          </Field>
          <Field label="Hour of day">
            <input {...num("hour_of_day")} min={0} max={23} />
          </Field>
        </div>
      </div>

      <div>
        <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-dim">Volume</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Duration (ms)">
            <input {...num("duration_ms")} min={0} />
          </Field>
          <Field label="Total bytes">
            <input {...num("total_bytes")} min={0} />
          </Field>
          <Field label="Forward packets">
            <input {...num("fwd_packets")} min={0} />
          </Field>
          <Field label="Backward packets">
            <input {...num("bwd_packets")} min={0} />
          </Field>
          <Field label="Packet size mean">
            <input {...num("packet_size_mean")} min={0} />
          </Field>
          <Field label="Packet size std">
            <input {...num("packet_size_std")} min={0} />
          </Field>
        </div>
      </div>

      <div>
        <p className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted-dim">Flags &amp; behavior</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="SYN count">
            <input {...num("syn_count")} min={0} />
          </Field>
          <Field label="FIN count">
            <input {...num("fin_count")} min={0} />
          </Field>
          <Field label="RST count">
            <input {...num("rst_count")} min={0} />
          </Field>
          <Field label="Unique dst ports">
            <input {...num("unique_dst_ports")} min={0} />
          </Field>
          <Field label="Payload entropy (0-8)">
            <input {...num("payload_entropy")} min={0} max={8} step={0.1} />
          </Field>
          <Field label="Over VPN?">
            <select
              className={inputClass}
              value={flow.is_vpn ? "yes" : "no"}
              onChange={(e) => set("is_vpn", e.target.value === "yes")}
            >
              <option value="no">No</option>
              <option value="yes">Yes</option>
            </select>
          </Field>
        </div>
      </div>
    </div>
  );
}
