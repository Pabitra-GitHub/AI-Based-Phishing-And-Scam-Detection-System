const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'medium',
  timeStyle: 'short',
});

const shortTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'short',
  timeStyle: 'short',
});

function parseDate(value: string): Date {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw new Error(`Invalid date value: ${value}`);
  }
  return date;
}

export function formatDateTime(value: string): string {
  return dateTimeFormatter.format(parseDate(value));
}

export function formatShortTime(value: string): string {
  return shortTimeFormatter.format(parseDate(value));
}
