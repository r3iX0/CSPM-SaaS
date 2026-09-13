import { createContext, useContext, useMemo, useState, type ReactNode } from "react";

import { ScanWizard } from "@/components/scans/ScanWizard";

type ScanWizardControls = {
  /** Open on the first step, or on review when a connection is already chosen. */
  start: (connectionId?: string) => void;
  /** Open on a scan that is already running, or has just finished. */
  watch: (scanId: string) => void;
};

const ScanWizardContext = createContext<ScanWizardControls>({
  start: () => {},
  watch: () => {},
});

/**
 * Where a scan is started and followed, held above every page.
 *
 * In the shell rather than on the scans page because a scan outlives the page
 * it was started from. Closing the panel minimises it rather than abandoning
 * it: the scan it was following stays remembered here, and the header's scan
 * indicator reopens the same live view.
 *
 * Each `start` opens a fresh session. The body is keyed on it, so a wizard
 * reopened after a finished scan begins at the first step rather than
 * inheriting the choices -- and the error -- of the last one, without an effect
 * resetting state after the fact.
 */
export function ScanWizardProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const [session, setSession] = useState(0);
  const [scanId, setScanId] = useState<string | null>(null);
  const [connectionId, setConnectionId] = useState<string | null>(null);

  const controls = useMemo<ScanWizardControls>(
    () => ({
      start: (id) => {
        setScanId(null);
        setConnectionId(id ?? null);
        setSession((n) => n + 1);
        setOpen(true);
      },
      watch: (id) => {
        setScanId(id);
        setSession((n) => n + 1);
        setOpen(true);
      },
    }),
    [],
  );

  return (
    <ScanWizardContext.Provider value={controls}>
      {children}
      <ScanWizard
        key={session}
        open={open}
        onOpenChange={setOpen}
        scanId={scanId}
        initialConnectionId={connectionId}
        onScanStarted={setScanId}
        onRunAnother={() => controls.start()}
      />
    </ScanWizardContext.Provider>
  );
}

/** Opens the scan wizard. A no-op outside the shell, so a page renders on its own in tests. */
export function useScanWizard(): ScanWizardControls {
  return useContext(ScanWizardContext);
}
