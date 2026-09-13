import { ChevronLeftIcon, ChevronRightIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Pagination,
  PaginationContent,
  PaginationEllipsis,
  PaginationItem,
} from "@/components/ui/pagination";

/**
 * How far apart the current page and an edge page may be before the numbers
 * between them are replaced by a gap. Two either side keeps the control the
 * same width whether the reader is on page 2 or page 40.
 */
const WINDOW = 1;

/**
 * The page numbers to draw, with `null` standing for a gap.
 *
 * Always the first and last page, always the window around the current one.
 * The first and last are what make this better than "Previous / Next": on a
 * findings list of four hundred rows, "how many pages is this" and "take me to
 * the end" were both questions the old control could not answer.
 */
function pageList(page: number, pages: number): (number | null)[] {
  const wanted = new Set<number>([0, pages - 1]);
  for (let i = page - WINDOW; i <= page + WINDOW; i++) {
    if (i >= 0 && i < pages) wanted.add(i);
  }

  const sorted = [...wanted].sort((a, b) => a - b);
  const out: (number | null)[] = [];
  let previous: number | null = null;
  for (const value of sorted) {
    if (previous !== null && value - previous > 1) out.push(null);
    out.push(value);
    previous = value;
  }
  return out;
}

/**
 * One pager for every paged list in the product.
 *
 * Four pages had grown their own — the same two buttons and a "3 / 9" between
 * them, copied and drifting. They shared a real limitation as well as their
 * markup: a reader could step through pages but never jump, so reaching the end
 * of a four-hundred-row findings list meant eight clicks and eight round trips.
 *
 * Pages are zero-based here because that is what the `offset` calculation on
 * every caller uses; the labels are one-based because that is what a person
 * counts. Keeping the conversion in one place is most of the reason this exists.
 *
 * Buttons rather than the primitive's anchors: paging is component state in
 * this app, not a URL, so an `<a>` with no `href` would be a control the
 * keyboard cannot reach. The `nav` and the list around them still come from the
 * primitive, which is what carries the landmark and the "pagination" name.
 */
export function Pager({
  page,
  pages,
  onPage,
  className,
}: {
  /** Zero-based. */
  page: number;
  pages: number;
  onPage: (page: number) => void;
  className?: string;
}) {
  if (pages <= 1) return null;

  return (
    <Pagination className={className}>
      <PaginationContent>
        <PaginationItem>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Previous page"
            disabled={page === 0}
            onClick={() => onPage(Math.max(0, page - 1))}
          >
            <ChevronLeftIcon />
          </Button>
        </PaginationItem>

        {pageList(page, pages).map((value, index) =>
          value === null ? (
            <PaginationItem key={`gap-${index}`}>
              <PaginationEllipsis />
            </PaginationItem>
          ) : (
            <PaginationItem key={value}>
              <Button
                variant={value === page ? "outline" : "ghost"}
                size="icon-sm"
                className="tabular-nums"
                // The current page is still a button rather than plain text:
                // it keeps the row's rhythm, and `aria-current` is what says
                // it is where you are.
                aria-current={value === page ? "page" : undefined}
                aria-label={`Page ${value + 1}`}
                onClick={() => onPage(value)}
              >
                {value + 1}
              </Button>
            </PaginationItem>
          ),
        )}

        <PaginationItem>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Next page"
            disabled={page + 1 >= pages}
            onClick={() => onPage(page + 1)}
          >
            <ChevronRightIcon />
          </Button>
        </PaginationItem>
      </PaginationContent>
    </Pagination>
  );
}

/**
 * The pager for a list that does not know how long it is.
 *
 * The changes feed is windowed by date rather than counted, so there is no
 * total to draw numbers from — and inventing one would be a claim the API never
 * made. Previous and Next, and nothing that implies a length.
 */
export function StepPager({
  page,
  hasMore,
  onPage,
  className,
}: {
  page: number;
  hasMore: boolean;
  onPage: (page: number) => void;
  className?: string;
}) {
  if (page === 0 && !hasMore) return null;

  return (
    <Pagination className={className}>
      <PaginationContent>
        <PaginationItem>
          <Button
            variant="outline"
            size="sm"
            disabled={page === 0}
            onClick={() => onPage(Math.max(0, page - 1))}
          >
            <ChevronLeftIcon data-icon="inline-start" />
            Previous
          </Button>
        </PaginationItem>
        <PaginationItem>
          <Button
            variant="outline"
            size="sm"
            disabled={!hasMore}
            onClick={() => onPage(page + 1)}
          >
            Next
            <ChevronRightIcon data-icon="inline-end" />
          </Button>
        </PaginationItem>
      </PaginationContent>
    </Pagination>
  );
}
