defmodule Ret.TRTCUserSig do
  @tls_ver "2.0"
  @tls_default_expire 86400 * 180
  @tls_hmac_alg :sha256
  @tls_hmac_delimiter "\n"

  @tls_ver_key "TLS.ver"
  @tls_identifier_key "TLS.identifier"
  @tls_sdkappid_key "TLS.sdkappid"
  @tls_time_key "TLS.time"
  @tls_expire_key "TLS.expire"
  @tls_sig_key  "TLS.sig"

  def generate(%{ userid: _ } = params) do
    params
    |> Map.put(:sdk_app_id, sdk_app_id())
    |> Map.put(:sdk_secret_key, sdk_secret_key())
    |> Map.put(:expire, @tls_default_expire)
    |> Map.put(:time, current_time())
    |> calculate
  end

  def generate(%{ userid: _, expire: _ } = params) do
    params
    |> Map.put(:sdk_app_id, sdk_app_id())
    |> Map.put(:sdk_secret_key, sdk_secret_key())
    |> Map.put(:time, current_time())
    |> calculate
  end

  defp calculate(%{ sdk_app_id: _, sdk_secret_key: sdk_secret_key, userid: _, time: _, expire: _ } = params) do
    params
    |> Map.put(:signeture, hmac(sdk_secret_key, params))
    |> json
    |> :zlib.compress
    |> base64_url_encode
  end

  defp json(%{ sdk_app_id: sdk_app_id, userid: userid, time: time, expire: expire, signeture: signeture }) do
    %{
      @tls_ver_key => @tls_ver,
      @tls_identifier_key => userid,
      @tls_sdkappid_key => sdk_app_id,
      @tls_time_key => time,
      @tls_expire_key => expire,
      @tls_sig_key => signeture,
    }
    |> Poison.encode!
  end

  defp hmac(secret, %{ sdk_app_id: sdk_app_id, userid: identifier, time: time, expire: expire } = _) do
    text =
      [
        "#{@tls_identifier_key}:#{identifier}",
        "#{@tls_sdkappid_key}:#{sdk_app_id}",
        "#{@tls_time_key}:#{time}",
        "#{@tls_expire_key}:#{expire}",
      ]
      |> Enum.reduce("", fn str, cur -> (cur <> str <> @tls_hmac_delimiter) end)

    :crypto.mac(:hmac, @tls_hmac_alg, secret, text) |> Base.encode64
  end

  defp base64_url_encode(bin) do
    bin
    |> Base.encode64
    |> String.replace("+", "*")
    |> String.replace("/", "-")
    |> String.replace("=", "_")
  end

  def sdk_app_id do
    Application.get_env(:ret, Ret.TRTCUserSig)[:trtc_sdk_app_id]
    |> String.to_integer
  end

  defp sdk_secret_key do
    Application.get_env(:ret, Ret.TRTCUserSig)[:trtc_sdk_secret_key]
  end

  defp current_time do
    DateTime.now!("Etc/UTC") |> DateTime.to_unix()
  end
end
