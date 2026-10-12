import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

/**
 * Picks a day from a `DatePicker`, by the label of its field.
 *
 * The calendar names each day in full ("Friday, October 9th, 2026"), so the
 * day is found by that name rather than by its number, which a month shows
 * twice when it draws the days around it.
 */
export async function pickDay(label: string, day: string): Promise<void> {
  const [year, month, date] = day.split("-").map(Number);
  if (year === undefined || month === undefined || date === undefined) {
    throw new Error(`Not a day: ${day}`);
  }
  const monthName = new Date(year, month - 1, date).toLocaleDateString("en-US", { month: "long" });
  await userEvent.click(screen.getByLabelText(label));
  await userEvent.click(
    await screen.findByRole("button", {
      name: new RegExp(`${monthName} ${date}(st|nd|rd|th), ${year}`),
    }),
  );
}
