"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Radar,
  ListTree,
  Waypoints,
  Database,
  Info,
  ShieldHalf,
  Activity,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard },
  { href: "/detect", label: "Detect", icon: Radar },
  { href: "/live", label: "Live Capture", icon: Activity },
  { href: "/threat-log", label: "Threat Log", icon: ListTree },
  { href: "/clusters", label: "Clusters", icon: Waypoints },
  { href: "/datasets", label: "Datasets", icon: Database },
  { href: "/about", label: "About", icon: Info },
];

export default function Nav() {
  const pathname = usePathname();

  return (
    <aside className="hidden md:flex md:w-60 md:flex-col md:border-r md:border-border md:bg-surface/60 md:backdrop-blur-sm">
      <div className="flex items-center gap-2 px-5 py-5 border-b border-border">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-accent/10 text-accent">
          <ShieldHalf size={18} />
        </div>
        <div>
          <p className="text-sm font-semibold tracking-tight text-foreground">NetSentry</p>
          <p className="text-[11px] text-muted-dim leading-none">explainable NIDS</p>
        </div>
      </div>

      <nav className="flex-1 space-y-1 px-3 py-4">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                active
                  ? "bg-accent/10 text-accent font-medium"
                  : "text-muted hover:bg-surface-raised hover:text-foreground"
              }`}
            >
              <Icon size={16} strokeWidth={2} />
              {label}
            </Link>
          );
        })}
      </nav>

      <div className="border-t border-border px-5 py-4 text-[11px] text-muted-dim">
        <p>Ayush Gupta (23BCE0157)</p>
        <p>Kartikay Chauhan (24BCE0689)</p>
      </div>
    </aside>
  );
}
