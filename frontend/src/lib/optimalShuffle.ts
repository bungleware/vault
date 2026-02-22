/**
 * Optimal Playlist Shuffling Algorithm
 *
 * Based on the algorithm described by Ruud van Asseldonk:
 * https://ruudvanasseldonk.com/2025/01/04/an-algorithm-for-optimal-playlist-shuffling
 *
 * This algorithm avoids playing the same artist twice in a row when possible,
 * unlike simple random shuffling. It's provably optimal in the sense that it
 * minimizes consecutive plays by the same artist.
 */

export interface ShuffleableTrack {
  artist?: string | null;
  [key: string]: any;
}

/**
 * Splits an array into n roughly equal parts.
 * If the array length is not divisible by n, some parts get one extra element.
 * The parts that get extra elements are selected randomly.
 */
function splitIntoEqualParts<T>(arr: T[], n: number): T[][] {
  if (n <= 0) return [arr];
  if (n >= arr.length) return arr.map(item => [item]);

  const baseSize = Math.floor(arr.length / n);
  const remainder = arr.length % n;

  // Determine which parts get an extra element
  const extraIndices = new Set<number>();
  const indices = Array.from({ length: n }, (_, i) => i);
  // Shuffle indices to randomly select which parts get extra elements
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  for (let i = 0; i < remainder; i++) {
    extraIndices.add(indices[i]);
  }

  const parts: T[][] = [];
  let currentIndex = 0;

  for (let i = 0; i < n; i++) {
    const size = baseSize + (extraIndices.has(i) ? 1 : 0);
    parts.push(arr.slice(currentIndex, currentIndex + size));
    currentIndex += size;
  }

  return parts;
}

/**
 * Interleaves two lists, distributing the smaller list into the larger one.
 * This minimizes consecutive tracks from the larger list.
 *
 * @param x - First list
 * @param y - Second list
 * @returns Interleaved list
 */
function interleave<T>(x: T[], y: T[]): T[] {
  // Ensure x is the larger list (or equal)
  if (y.length > x.length) {
    [x, y] = [y, x];
  }

  const n = x.length;
  const m = y.length;

  // Special case: if both lists are equal length, flip a coin for which goes first
  if (n === m && m > 0) {
    const xFirst = Math.random() < 0.5;
    const result: T[] = [];
    for (let i = 0; i < n; i++) {
      if (xFirst) {
        result.push(x[i]);
        result.push(y[i]);
      } else {
        result.push(y[i]);
        result.push(x[i]);
      }
    }
    return result;
  }

  // Split x into m+1 equal parts
  const numParts = m + 1;
  const xParts = splitIntoEqualParts(x, numParts);

  // Interleave: part of x, element of y, part of x, element of y, ..., part of x
  const result: T[] = [];
  for (let i = 0; i < xParts.length; i++) {
    result.push(...xParts[i]);
    if (i < y.length) {
      result.push(y[i]);
    }
  }

  return result;
}

/**
 * Finds all positions where an item appears consecutively in a list.
 * Returns indices of the start of each consecutive span.
 */
function findConsecutiveSpans<T>(arr: T[], compareFn: (a: T, b: T) => boolean): number[] {
  const spanStarts: number[] = [0]; // First element always starts a span

  for (let i = 1; i < arr.length; i++) {
    if (!compareFn(arr[i], arr[i - 1])) {
      spanStarts.push(i);
    }
  }

  return spanStarts;
}

/**
 * Breaks an array into spans at every place where consecutive items match.
 * If we have fewer than targetSpans, randomly breaks up spans until we reach targetSpans.
 */
function breakIntoSpans<T>(arr: T[], targetSpans: number, compareFn: (a: T, b: T) => boolean): T[][] {
  if (arr.length === 0) return [];
  if (targetSpans <= 1) return [arr];

  // Find natural break points (where consecutive items differ)
  const spanIndices = findConsecutiveSpans(arr, compareFn);

  // If we already have enough natural spans, use them
  if (spanIndices.length >= targetSpans) {
    const spans: T[][] = [];
    for (let i = 0; i < spanIndices.length; i++) {
      const start = spanIndices[i];
      const end = i < spanIndices.length - 1 ? spanIndices[i + 1] : arr.length;
      spans.push(arr.slice(start, end));
    }
    return spans;
  }

  // We need to break up some consecutive runs to create more spans
  // Start with natural spans
  let spans: T[][] = [];
  for (let i = 0; i < spanIndices.length; i++) {
    const start = spanIndices[i];
    const end = i < spanIndices.length - 1 ? spanIndices[i + 1] : arr.length;
    spans.push(arr.slice(start, end));
  }

  // Randomly break up spans until we have targetSpans
  while (spans.length < targetSpans) {
    // Find spans that can be broken (length > 1)
    const breakableIndices = spans
      .map((span, idx) => ({ idx, len: span.length }))
      .filter(({ len }) => len > 1);

    if (breakableIndices.length === 0) break; // Can't break any further

    // Pick a random span to break
    const randomIdx = breakableIndices[Math.floor(Math.random() * breakableIndices.length)].idx;
    const spanToBreak = spans[randomIdx];

    // Break it at a random point (not at the edges)
    const breakPoint = 1 + Math.floor(Math.random() * (spanToBreak.length - 1));
    const leftPart = spanToBreak.slice(0, breakPoint);
    const rightPart = spanToBreak.slice(breakPoint);

    // Replace the span with two smaller spans
    spans = [
      ...spans.slice(0, randomIdx),
      leftPart,
      rightPart,
      ...spans.slice(randomIdx + 1),
    ];
  }

  return spans;
}

/**
 * Intersperses list y into list x by breaking x into spans and interleaving.
 * This is used when x is larger than y but we want to break up consecutive items in x.
 *
 * @param x - The list to break into spans
 * @param y - The list to intersperse
 * @param compareFn - Function to determine if two items should be considered consecutive
 * @returns Interspersed list
 */
function intersperse<T>(x: T[], y: T[], compareFn: (a: T, b: T) => boolean): T[] {
  const m = y.length;
  const targetSpans = m + 1;

  // Break x into spans
  const xSpans = breakIntoSpans(x, targetSpans, compareFn);

  // Interleave spans with y elements
  const result: T[] = [];
  for (let i = 0; i < xSpans.length; i++) {
    result.push(...xSpans[i]);
    if (i < y.length) {
      result.push(y[i]);
    }
  }

  return result;
}

/**
 * Gets the artist identifier for a track, normalizing null/undefined to a unique key.
 */
function getArtistKey(track: ShuffleableTrack): string {
  return track.artist?.trim() || '__unknown__';
}

/**
 * Partitions tracks by artist.
 */
function partitionByArtist<T extends ShuffleableTrack>(tracks: T[]): Map<string, T[]> {
  const partitions = new Map<string, T[]>();

  for (const track of tracks) {
    const artist = getArtistKey(track);
    if (!partitions.has(artist)) {
      partitions.set(artist, []);
    }
    partitions.get(artist)!.push(track);
  }

  return partitions;
}

/**
 * Performs optimal shuffle on a playlist.
 *
 * This algorithm:
 * 1. Partitions tracks by artist
 * 2. Sorts partitions by size (ascending)
 * 3. Incrementally merges partitions using interleave or intersperse
 * 4. Returns a shuffled playlist that minimizes consecutive plays by the same artist
 *
 * @param tracks - Array of tracks to shuffle
 * @returns Optimally shuffled array of tracks
 */
export function optimalShuffle<T extends ShuffleableTrack>(tracks: T[]): T[] {
  if (tracks.length <= 1) return [...tracks];

  // Partition by artist
  const partitions = partitionByArtist(tracks);

  // Convert to array of [artist, tracks[]] and sort by size (ascending)
  let sortedPartitions = Array.from(partitions.entries())
    .map(([artist, artistTracks]) => ({ artist, tracks: artistTracks }));

  // Shuffle each artist's tracks individually (within-artist shuffle)
  sortedPartitions = sortedPartitions.map(partition => ({
    ...partition,
    tracks: shuffleArray(partition.tracks),
  }));

  // Sort by size, breaking ties randomly
  sortedPartitions.sort((a, b) => {
    const diff = a.tracks.length - b.tracks.length;
    if (diff !== 0) return diff;
    // Random tie-breaking
    return Math.random() - 0.5;
  });

  // Incrementally merge partitions
  let result: T[] = [];

  for (const partition of sortedPartitions) {
    const n = partition.tracks.length;
    const m = result.length;

    if (m === 0) {
      // First partition, just use it as-is
      result = partition.tracks;
    } else if (n >= m) {
      // Use interleave when new partition is larger or equal
      result = interleave(partition.tracks, result);
    } else {
      // Use intersperse when result is larger
      // We need to check if consecutive tracks in result are from the same artist
      const compareFn = (a: T, b: T) => getArtistKey(a) === getArtistKey(b);
      result = intersperse(result, partition.tracks, compareFn);
    }
  }

  return result;
}

/**
 * Simple Fisher-Yates shuffle for within-artist randomization.
 */
function shuffleArray<T>(arr: T[]): T[] {
  const result = [...arr];
  for (let i = result.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

/**
 * Creates a shuffled order for playlist tracks.
 * Instead of shuffling the tracks themselves, this returns the shuffled playlist
 * to be used for playback order.
 *
 * @param tracks - Original track array
 * @returns Shuffled track array
 */
export function createShuffledPlaylist<T extends ShuffleableTrack>(tracks: T[]): T[] {
  return optimalShuffle(tracks);
}
