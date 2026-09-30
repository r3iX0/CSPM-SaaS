import * as React from "react"

import { m, type HTMLMotionProps } from "motion/react"

import { cn } from "@/lib/utils"

function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div
      data-slot="table-container"
      className="relative w-full overflow-x-auto"
    >
      <table
        data-slot="table"
        className={cn("w-full caption-bottom text-sm", className)}
        {...props}
      />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<"thead">) {
  return (
    <thead
      data-slot="table-header"
      // A quiet band rather than a bold row: column names are how a table is
      // read, not what it says, so they sit back and let the rows lead.
      className={cn("bg-muted/40 [&_tr]:border-b [&_tr]:hover:bg-transparent", className)}
      {...props}
    />
  )
}

function TableBody({ className, ...props }: React.ComponentProps<"tbody">) {
  return (
    <tbody
      data-slot="table-body"
      className={cn("[&_tr:last-child]:border-0", className)}
      {...props}
    />
  )
}

function TableFooter({ className, ...props }: React.ComponentProps<"tfoot">) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn(
        "border-t bg-muted/50 font-medium [&>tr]:last:border-b-0",
        className
      )}
      {...props}
    />
  )
}

const tableRowClass =
  "border-b transition-colors hover:bg-muted/60 has-aria-expanded:bg-muted/60 data-[state=selected]:bg-muted"

function TableRow({ className, ...props }: React.ComponentProps<"tr">) {
  return (
    <tr data-slot="table-row" className={cn(tableRowClass, className)} {...props} />
  )
}

/**
 * A row that can slide to its new place when the rows around it change
 * (`listLayout`, DECISIONS.md §179). CloudGuard's own addition: the registry
 * has no motion rows, and a `tr` cannot be wrapped without breaking the table.
 */
function MotionTableRow({ className, ...props }: HTMLMotionProps<"tr">) {
  return (
    <m.tr data-slot="table-row" className={cn(tableRowClass, className)} {...props} />
  )
}

function TableHead({ className, ...props }: React.ComponentProps<"th">) {
  return (
    <th
      data-slot="table-head"
      className={cn(
        "h-10 px-3 text-left align-middle text-caption font-normal whitespace-nowrap text-muted-foreground first:pl-5 last:pr-5 [&:has([role=checkbox])]:pr-0",
        className
      )}
      {...props}
    />
  )
}

function TableCell({ className, ...props }: React.ComponentProps<"td">) {
  return (
    <td
      data-slot="table-cell"
      className={cn(
        "px-3 py-3 align-middle whitespace-nowrap first:pl-5 last:pr-5 [&:has([role=checkbox])]:pr-0",
        className
      )}
      {...props}
    />
  )
}

function TableCaption({
  className,
  ...props
}: React.ComponentProps<"caption">) {
  return (
    <caption
      data-slot="table-caption"
      className={cn("mt-4 text-sm text-muted-foreground", className)}
      {...props}
    />
  )
}

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  MotionTableRow,
  TableCell,
  TableCaption,
}
