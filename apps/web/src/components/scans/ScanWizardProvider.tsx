import {
  createContext,
  lazy,
  Suspense,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useSearchParams } from "react-router-dom";

const ScanWizard = lazy(() =>
  import("@/components/scans/ScanWizard").then((module) => ({ default: module.ScanWizard })),
);

interface ScanWizardControls {
  /** Open on the first step, or on review when a connection is already chosen. */
  start: (connectionId?: string) => void;
  /** Open on a scan -- running, or finished and read as its result. */
  watch: (scanId: string) => void;
}

const ScanWizardContext = createContext<ScanWizardControls>({
  start: () => {},
  watch: () => {},
});

/** The search parameter that names the scan the wizard is open on. */
const SCAN_PARAM = "scan";

/**
 * Where a scan is started and followed, held above every page.
 *
 * In the shell rather than on the scans page because a scan outlives the page
 * it was started from. Closing the dialog minimises it rather than abandoning
 * it: the scan goes on, and the header's scan indicator reopens the same live
 * view.
 *
 * The scan the dialog is open on is in the URL (`?scan=`), so a scan is a link
 * -- pasted to a colleague, or surviving a reload mid-run -- on whatever page it
 * was opened over. Every change replaces the entry: opening a scan is not a
 * trail somebody retraces with Back. Choosing an environment is not in the
 * URL, because nothing has happened yet that a link could point at.
 *
 * Each `start` opens a fresh session. The dialog is keyed on it, so a wizard
 * reopened after a finished scan begins at the first step rather than
 * inheriting the choices -- and the error -- of the last one, without an effect
 * resetting state after the fact.
 *
 * Only this half is in the entry chunk. The dialog -- the pipeline, the result,
 * a finished scan's details -- is fetched the first time it opens and kept
 * mounted after, the command palette's arrangement (DECISIONS.md §149).
 */
export function ScanWizardProvider({ children }: { children: ReactNode }) {
  const [params, setParams] = useSearchParams();
  const [starting, setStarting] = useState(false);
  const [session, setSession] = useState(0);
  const [connectionId, setConnectionId] = useState<string | null>(null);

  const scanId = params.get(SCAN_PARAM);
  const open = starting || scanId !== null;
  // Mounted from the first opening on: closing is not a reason to fetch it
  // again, and staying mounted is what lets it animate out.
  const [wanted, setWanted] = useState(open);
  if (open && !wanted) setWanted(true);

  const controls = useMemo(() => {
    const setScan = (id: string | null) =>
      setParams(
        (previous) => {
          const next = new URLSearchParams(previous);
          if (id) next.set(SCAN_PARAM, id);
          else next.delete(SCAN_PARAM);
          return next;
        },
        { replace: true },
      );
    return {
      start: (id?: string) => {
        setScan(null);
        setConnectionId(id ?? null);
        setSession((n) => n + 1);
        setStarting(true);
      },
      // Once a scan exists the URL alone holds the dialog open, so following
      // any link out of it -- to the findings, to the history -- closes it.
      watch: (id: string) => {
        setStarting(false);
        setScan(id);
      },
      close: () => {
        setStarting(false);
        setScan(null);
      },
    };
  }, [setParams]);

  return (
    <ScanWizardContext.Provider value={controls}>
      {children}
      {wanted && (
        <Suspense fallback={null}>
          <ScanWizard
            key={session}
            open={open}
            onClose={controls.close}
            scanId={scanId}
            initialConnectionId={connectionId}
            onScanStarted={controls.watch}
            onRunAnother={() => controls.start()}
          />
        </Suspense>
      )}
    </ScanWizardContext.Provider>
  );
}

/** Opens the scan wizard. A no-op outside the shell, so a page renders on its own in tests. */
export function useScanWizard(): ScanWizardControls {
  return useContext(ScanWizardContext);
}
