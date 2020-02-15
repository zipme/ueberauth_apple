defmodule UeberauthApple do
  @default_expires_in 86400 * 180
  @public_key_url "https://appleid.apple.com/auth/keys"
  @alg "RS256"

  def fields_from_id_token(id_token) do
    with %{fields: %{"kid" => kid}} <- JOSE.JWT.peek_protected(id_token),
      {:ok, %{body: response_body}} <- HTTPoison.get(@public_key_url),
         {true, %JOSE.JWT{fields: fields}, _jws} <-
           Ueberauth.json_library().decode!(response_body)["keys"]
           |> find_key(kid)
           |> JOSE.JWT.verify(id_token)do
      {:ok, fields}
    else
      reason -> {:error, inspect(reason)}
    end
  end

  def verify_token(key, token) do
    JsonWebToken.verify(token, alg: @alg, key: key)
  end

  @doc """
  Generates client secret.
  """
  def generate_client_secret(
        %{client_id: client_id, key_id: key_id, team_id: team_id, private_key: private_key} =
          options
      ) do
    opts = Enum.into(options, %{expires_in: @default_expires_in})
    now = DateTime.utc_now() |> DateTime.to_unix()
    jwk = JOSE.JWK.from_pem(private_key)
    jws = %{"alg" => "ES256", "kid" => key_id}

    jwt = %{
      "iss" => team_id,
      "iat" => now,
      "exp" => now + opts[:expires_in],
      "aud" => "https://appleid.apple.com",
      "sub" => client_id
    }

    {_, token} = jwk |> JOSE.JWT.sign(jws, jwt) |> JOSE.JWS.compact()
    token
  end

  def generate_client_secret(opts) when is_list(opts),
    do: opts |> Enum.into(%{}) |> generate_client_secret()

  defp find_key(keys, kid) do
    Enum.find(keys, &(&1["kid"] == kid))
  end
end
