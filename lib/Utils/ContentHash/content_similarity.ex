defmodule DomainTwistex.Utils.ContentSimilarity do
  @moduledoc """
  Content-based similarity detection for web pages.

  Similar to dnstwist's ssdeep/tlsh fuzzy hashing, this module:
  1. Fetches HTML content from domains
  2. Normalizes the content (strips dynamic elements)
  3. Computes similarity using shingle-based Jaccard similarity

  This helps detect phishing pages that copy legitimate site content.
  """

  @default_timeout 5_000
  @shingle_size 5

  @doc """
  Fetches and caches the original domain's content for comparison.

  Call this once before analyzing permutations.

  ## Example
      {:ok, original} = ContentSimilarity.fetch_original("example.com")
  """
  def fetch_original(domain) do
    case fetch_content(domain) do
      {:ok, content} ->
        normalized = normalize_content(content)
        shingles = compute_shingles(normalized)
        {:ok, %{
          domain: domain,
          content: normalized,
          shingles: shingles,
          length: String.length(normalized)
        }}
      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Compares a permutation's content against the original.

  Returns similarity score 0-100 (100 = identical content).

  ## Example
      {:ok, original} = ContentSimilarity.fetch_original("example.com")
      {:ok, score} = ContentSimilarity.compare("examp1e.com", original)
      # => {:ok, 87}
  """
  def compare(domain, original_data) do
    case fetch_content(domain) do
      {:ok, content} ->
        normalized = normalize_content(content)
        shingles = compute_shingles(normalized)

        similarity = %{
          jaccard: jaccard_similarity(original_data.shingles, shingles),
          length_ratio: length_ratio(original_data.length, String.length(normalized)),
          structure: structure_similarity(original_data.content, normalized)
        }

        # Combined score (weighted average)
        score = round(
          similarity.jaccard * 0.6 +
          similarity.length_ratio * 0.2 +
          similarity.structure * 0.2
        )

        {:ok, %{score: score, details: similarity}}

      {:error, _reason} ->
        {:ok, %{score: 0, details: %{error: :fetch_failed}}}
    end
  end

  @doc """
  Quick check if content is similar enough to warrant attention.

  Returns true if similarity > threshold (default 50%).
  """
  def similar?(domain, original_data, threshold \\ 50) do
    case compare(domain, original_data) do
      {:ok, %{score: score}} -> score >= threshold
      _ -> false
    end
  end

  # Fetch HTML content from a domain
  defp fetch_content(domain) do
    urls = ["https://#{domain}", "http://#{domain}"]

    headers = [
      {"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"},
      {"accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
      {"accept-language", "en-US,en;q=0.5"}
    ]

    Enum.reduce_while(urls, {:error, :all_failed}, fn url, _acc ->
      case Req.get(url,
             headers: headers,
             receive_timeout: @default_timeout,
             connect_options: [transport_opts: [verify: :verify_none]],
             max_retries: 1,
             redirect: true,
             max_redirects: 5
           ) do
        {:ok, %Req.Response{status: status, body: body}} when status in 200..299 ->
          {:halt, {:ok, body}}
        {:ok, %Req.Response{status: status}} ->
          {:cont, {:error, {:http_error, status}}}
        {:error, reason} ->
          {:cont, {:error, reason}}
      end
    end)
  end

  # Normalize HTML content for comparison
  # Strips dynamic elements, whitespace, and URL-specific content
  defp normalize_content(html) when is_binary(html) do
    html
    |> String.downcase()
    # Remove script and style blocks
    |> remove_between("<script", "</script>")
    |> remove_between("<style", "</style>")
    |> remove_between("<!--", "-->")
    # Remove common dynamic attributes
    |> String.replace(~r/\s+(id|class|style|onclick|onload|data-\w+)="[^"]*"/, "")
    |> String.replace(~r/\s+(id|class|style|onclick|onload|data-\w+)='[^']*'/, "")
    # Normalize URLs (they'll differ between original and phishing)
    |> String.replace(~r/(href|src|action)="[^"]*"/, "\\1=\"\"")
    |> String.replace(~r/(href|src|action)='[^']*'/, "\\1=''")
    # Normalize whitespace
    |> String.replace(~r/\s+/, " ")
    |> String.trim()
  end
  defp normalize_content(_), do: ""

  defp remove_between(text, start_tag, end_tag) do
    regex = Regex.compile!("#{Regex.escape(start_tag)}.*?#{Regex.escape(end_tag)}", [:dotall])
    String.replace(text, regex, "")
  end

  # Compute n-gram shingles for Jaccard similarity
  defp compute_shingles(text) do
    text
    |> String.graphemes()
    |> Enum.chunk_every(@shingle_size, 1, :discard)
    |> Enum.map(&Enum.join/1)
    |> MapSet.new()
  end

  # Jaccard similarity: |A ∩ B| / |A ∪ B|
  defp jaccard_similarity(set1, set2) do
    intersection = MapSet.intersection(set1, set2) |> MapSet.size()
    union = MapSet.union(set1, set2) |> MapSet.size()

    if union == 0 do
      0.0
    else
      intersection / union * 100
    end
  end

  # Compare content lengths (similar length = higher score)
  defp length_ratio(len1, len2) do
    if len1 == 0 or len2 == 0 do
      0.0
    else
      min(len1, len2) / max(len1, len2) * 100
    end
  end

  # Structure similarity based on HTML tag distribution
  defp structure_similarity(html1, html2) do
    tags1 = extract_tag_counts(html1)
    tags2 = extract_tag_counts(html2)

    all_tags = Map.keys(tags1) ++ Map.keys(tags2) |> Enum.uniq()

    if length(all_tags) == 0 do
      0.0
    else
      similarities = Enum.map(all_tags, fn tag ->
        count1 = Map.get(tags1, tag, 0)
        count2 = Map.get(tags2, tag, 0)
        if count1 == 0 and count2 == 0 do
          1.0
        else
          min(count1, count2) / max(count1, count2)
        end
      end)

      Enum.sum(similarities) / length(similarities) * 100
    end
  end

  defp extract_tag_counts(html) do
    Regex.scan(~r/<(\w+)[\s>]/, html)
    |> Enum.map(fn [_, tag] -> tag end)
    |> Enum.frequencies()
  end
end
