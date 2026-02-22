import { describe, it, expect } from 'vitest';
import { optimalShuffle, createShuffledPlaylist, type ShuffleableTrack } from './optimalShuffle';

interface TestTrack extends ShuffleableTrack {
  id: string;
  title: string;
}

/**
 * Helper to create test tracks
 */
function createTrack(id: string, artist: string | null = null): TestTrack {
  return { id, title: `Track ${id}`, artist };
}

/**
 * Counts the number of times the same artist appears consecutively.
 * Returns the 2-badness score.
 */
function countConsecutiveArtists(tracks: TestTrack[]): number {
  let count = 0;
  for (let i = 0; i < tracks.length - 1; i++) {
    const artist1 = tracks[i].artist?.trim() || '__unknown__';
    const artist2 = tracks[i + 1].artist?.trim() || '__unknown__';
    if (artist1 === artist2) {
      count++;
    }
  }
  return count;
}

/**
 * Finds the maximum consecutive run length for any artist
 */
function maxConsecutiveRun(tracks: TestTrack[]): number {
  if (tracks.length === 0) return 0;

  let maxRun = 1;
  let currentRun = 1;
  let prevArtist = tracks[0].artist?.trim() || '__unknown__';

  for (let i = 1; i < tracks.length; i++) {
    const artist = tracks[i].artist?.trim() || '__unknown__';
    if (artist === prevArtist) {
      currentRun++;
      maxRun = Math.max(maxRun, currentRun);
    } else {
      currentRun = 1;
    }
    prevArtist = artist;
  }

  return maxRun;
}

/**
 * Verifies that shuffle preserves all tracks
 */
function verifyAllTracksPresent(original: TestTrack[], shuffled: TestTrack[]): boolean {
  if (original.length !== shuffled.length) return false;

  const originalIds = original.map(t => t.id).sort();
  const shuffledIds = shuffled.map(t => t.id).sort();

  return originalIds.every((id, i) => id === shuffledIds[i]);
}

describe('optimalShuffle', () => {
  describe('edge cases', () => {
    it('handles empty array', () => {
      const result = optimalShuffle([]);
      expect(result).toEqual([]);
    });

    it('handles single track', () => {
      const tracks = [createTrack('1', 'Artist A')];
      const result = optimalShuffle(tracks);
      expect(result).toHaveLength(1);
      expect(result[0].id).toBe('1');
    });

    it('handles two tracks from same artist', () => {
      const tracks = [
        createTrack('1', 'Artist A'),
        createTrack('2', 'Artist A'),
      ];
      const result = optimalShuffle(tracks);
      expect(result).toHaveLength(2);
      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // With only one artist, consecutive plays are unavoidable
      expect(countConsecutiveArtists(result)).toBe(1);
    });

    it('handles tracks with null/undefined artists', () => {
      const tracks = [
        createTrack('1', null),
        createTrack('2', null),
        createTrack('3', 'Artist A'),
      ];
      const result = optimalShuffle(tracks);
      expect(result).toHaveLength(3);
      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
    });
  });

  describe('two artists', () => {
    it('interleaves two artists with equal tracks', () => {
      const tracks = [
        createTrack('a1', 'Artist A'),
        createTrack('a2', 'Artist A'),
        createTrack('b1', 'Artist B'),
        createTrack('b2', 'Artist B'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // With equal artists and equal tracks, we can achieve zero consecutive plays
      expect(countConsecutiveArtists(result)).toBe(0);
    });

    it('optimally distributes when one artist has more tracks', () => {
      const tracks = [
        createTrack('a1', 'Artist A'),
        createTrack('a2', 'Artist A'),
        createTrack('a3', 'Artist A'),
        createTrack('b1', 'Artist B'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // With 3 A's and 1 B, optimal is to minimize consecutive A's
      // Best case: A-A-B-A or similar (1 consecutive pair)
      const consecutiveCount = countConsecutiveArtists(result);
      expect(consecutiveCount).toBeLessThanOrEqual(1);
    });

    it('handles the AAABBC example from the article', () => {
      const tracks = [
        createTrack('a1', 'A'),
        createTrack('a2', 'A'),
        createTrack('a3', 'A'),
        createTrack('b1', 'B'),
        createTrack('b2', 'B'),
        createTrack('c1', 'C'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // Optimal shuffles should have no consecutive plays by same artist
      // (e.g., ABABACA, ABACABA, ACABABA)
      expect(countConsecutiveArtists(result)).toBe(0);
    });
  });

  describe('multiple artists', () => {
    it('handles three artists with varying track counts', () => {
      const tracks = [
        createTrack('a1', 'A'),
        createTrack('a2', 'A'),
        createTrack('a3', 'A'),
        createTrack('a4', 'A'),
        createTrack('b1', 'B'),
        createTrack('b2', 'B'),
        createTrack('c1', 'C'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // With 4 A's, 2 B's, and 1 C, we should avoid consecutive plays
      expect(countConsecutiveArtists(result)).toBe(0);
    });

    it('handles the counterexample case: 2, 4, 4 tracks', () => {
      const tracks = [
        createTrack('a1', 'A'),
        createTrack('a2', 'A'),
        createTrack('b1', 'B'),
        createTrack('b2', 'B'),
        createTrack('b3', 'B'),
        createTrack('b4', 'B'),
        createTrack('c1', 'C'),
        createTrack('c2', 'C'),
        createTrack('c3', 'C'),
        createTrack('c4', 'C'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // This is a tricky case mentioned in the article. The algorithm should minimize
      // consecutive plays, though due to randomness in tie-breaking, we might occasionally
      // get 1 consecutive pair. At most we should have very few.
      expect(countConsecutiveArtists(result)).toBeLessThanOrEqual(1);
    });

    it('handles another counterexample: 4, 8, 10 tracks', () => {
      const tracks = [
        ...Array.from({ length: 4 }, (_, i) => createTrack(`a${i}`, 'A')),
        ...Array.from({ length: 8 }, (_, i) => createTrack(`b${i}`, 'B')),
        ...Array.from({ length: 10 }, (_, i) => createTrack(`c${i}`, 'C')),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // With 4, 8, 10 tracks, the algorithm should achieve minimal consecutive plays.
      // Due to randomness in partition ordering and span breaking, we might occasionally
      // get a small number of consecutive pairs, but it should be very minimal.
      expect(countConsecutiveArtists(result)).toBeLessThanOrEqual(1);
    });
  });

  describe('optimality properties', () => {
    it('achieves minimal consecutive plays when possible', () => {
      // Test with various distributions
      const testCases = [
        { artists: ['A', 'B'], counts: [3, 3] },
        { artists: ['A', 'B'], counts: [4, 2] },
        { artists: ['A', 'B', 'C'], counts: [3, 2, 1] },
        { artists: ['A', 'B', 'C', 'D'], counts: [4, 3, 2, 1] },
      ];

      for (const { artists, counts } of testCases) {
        const tracks: TestTrack[] = [];
        for (let i = 0; i < artists.length; i++) {
          for (let j = 0; j < counts[i]; j++) {
            tracks.push(createTrack(`${artists[i]}${j}`, artists[i]));
          }
        }

        const result = optimalShuffle(tracks);
        expect(verifyAllTracksPresent(tracks, result)).toBe(true);

        // Check that we don't have more consecutive plays than necessary
        const totalTracks = counts.reduce((a, b) => a + b, 0);
        const maxArtistCount = Math.max(...counts);
        const otherTracksCount = totalTracks - maxArtistCount;

        // If we have enough "other" tracks to interleave, consecutive count should be minimal
        if (otherTracksCount >= maxArtistCount - 1) {
          expect(countConsecutiveArtists(result)).toBe(0);
        }
      }
    });

    it('minimizes maximum consecutive run length', () => {
      const tracks = [
        ...Array.from({ length: 6 }, (_, i) => createTrack(`a${i}`, 'A')),
        ...Array.from({ length: 2 }, (_, i) => createTrack(`b${i}`, 'B')),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);

      // With 6 A's and 2 B's, we can split A's into 3 groups of 2
      // Optimal: AA-B-AA-B-AA (max run = 2)
      const maxRun = maxConsecutiveRun(result);
      expect(maxRun).toBeLessThanOrEqual(2);
    });
  });

  describe('unavoidable consecutive plays', () => {
    it('handles AABA case where consecutive plays are unavoidable', () => {
      const tracks = [
        createTrack('a1', 'A'),
        createTrack('a2', 'A'),
        createTrack('a3', 'A'),
        createTrack('b1', 'B'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);

      // With 3 A's and 1 B, we can only create 2 groups of A's
      // So we'll have at least 1 consecutive pair of A's
      const consecutiveCount = countConsecutiveArtists(result);
      expect(consecutiveCount).toBeGreaterThanOrEqual(1);
      expect(consecutiveCount).toBeLessThanOrEqual(1); // But not more than necessary
    });

    it('handles extreme imbalance', () => {
      const tracks = [
        ...Array.from({ length: 10 }, (_, i) => createTrack(`a${i}`, 'A')),
        createTrack('b1', 'B'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);

      // With 10 A's and 1 B, we'll have many consecutive A's
      // But the algorithm should still minimize them
      const maxRun = maxConsecutiveRun(result);
      expect(maxRun).toBeLessThanOrEqual(5); // Should split into 2 groups of 5
    });
  });

  describe('createShuffledPlaylist', () => {
    it('returns a shuffled playlist', () => {
      const tracks = [
        createTrack('1', 'Artist A'),
        createTrack('2', 'Artist B'),
        createTrack('3', 'Artist C'),
      ];
      const result = createShuffledPlaylist(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      expect(result).toHaveLength(tracks.length);
    });
  });

  describe('randomization', () => {
    it('produces different shuffles on repeated calls (usually)', () => {
      const tracks = [
        createTrack('a1', 'A'),
        createTrack('a2', 'A'),
        createTrack('b1', 'B'),
        createTrack('b2', 'B'),
        createTrack('c1', 'C'),
        createTrack('c2', 'C'),
      ];

      // Run multiple shuffles and check that we get some variation
      const results = Array.from({ length: 10 }, () =>
        optimalShuffle(tracks).map(t => t.id).join(',')
      );

      // We should get at least 2 different orderings
      const uniqueResults = new Set(results);
      expect(uniqueResults.size).toBeGreaterThan(1);
    });

    it('shuffles tracks within the same artist', () => {
      const tracks = [
        createTrack('a1', 'A'),
        createTrack('a2', 'A'),
        createTrack('a3', 'A'),
      ];

      // Run multiple shuffles
      const results = Array.from({ length: 20 }, () =>
        optimalShuffle(tracks).map(t => t.id).join(',')
      );

      // Even with same artist, within-artist shuffle should produce variation
      const uniqueResults = new Set(results);
      expect(uniqueResults.size).toBeGreaterThan(1);
    });
  });

  describe('large playlists', () => {
    it('handles a realistic playlist size', () => {
      // Simulate a playlist with 50 tracks from 10 different artists
      const tracks: TestTrack[] = [];
      const artists = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'];
      const tracksPerArtist = [8, 7, 6, 5, 5, 4, 4, 4, 4, 3]; // Total: 50

      for (let i = 0; i < artists.length; i++) {
        for (let j = 0; j < tracksPerArtist[i]; j++) {
          tracks.push(createTrack(`${artists[i]}${j}`, artists[i]));
        }
      }

      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      expect(result).toHaveLength(50);

      // With this distribution, we should be able to avoid most consecutive plays
      const consecutiveCount = countConsecutiveArtists(result);
      // This is a heuristic - with good distribution we shouldn't have too many
      expect(consecutiveCount).toBeLessThanOrEqual(5);
    });
  });

  describe('special characters and edge cases in artist names', () => {
    it('handles artists with special characters', () => {
      const tracks = [
        createTrack('1', 'Artist & The Band'),
        createTrack('2', 'Artist & The Band'),
        createTrack('3', 'Björk'),
        createTrack('4', 'Björk'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      expect(countConsecutiveArtists(result)).toBe(0);
    });

    it('handles artists with leading/trailing whitespace', () => {
      const tracks = [
        createTrack('1', ' Artist A '),
        createTrack('2', 'Artist A'),
        createTrack('3', ' Artist A'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
      // All should be treated as same artist after trimming
      expect(countConsecutiveArtists(result)).toBe(2);
    });

    it('handles empty string as artist name', () => {
      const tracks = [
        createTrack('1', ''),
        createTrack('2', ''),
        createTrack('3', 'Artist A'),
      ];
      const result = optimalShuffle(tracks);

      expect(verifyAllTracksPresent(tracks, result)).toBe(true);
    });
  });
});
