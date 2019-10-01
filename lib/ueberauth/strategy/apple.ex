defmodule Ueberauth.Strategy.Apple do
  @moduledoc """
  Apple Strategy for Überauth.
  """

  use Ueberauth.Strategy, uid_field: :uid, default_scope: "name email"

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra

  @allowed_client_ids Application.get_env(
                        :ueberauth,
                        Ueberauth.Strategy.Apple.OAuth
                      )[:allowed_client_ids]

  @doc """
  Handles initial request for Apple authentication.
  """
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)

    params =
      [scope: scopes]
      |> with_optional(:prompt, conn)
      |> with_optional(:access_type, conn)
      |> with_param(:access_type, conn)
      |> with_param(:prompt, conn)
      |> with_param(:state, conn)

    opts = oauth_client_options_from_conn(conn)
    redirect!(conn, Ueberauth.Strategy.Apple.OAuth.authorize_url!(params, opts))
  end

  @doc """
  Handles the callback from Apple.
  """
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    params = [code: code]
    opts = oauth_client_options_from_conn(conn)

    with {:ok, token} <- Ueberauth.Strategy.Apple.OAuth.get_access_token(params, opts),
         {:ok, user} <- user_from_id_token(token.other_params["id_token"]) do
      conn
      |> put_private(:apple_token, token)
      |> put_private(:apple_user, user)
    else
      {:error, {error_code, error_description}} ->
        set_errors!(conn, [error(error_code, error_description)])

      {:error, error} ->
        set_errors!(conn, [error(:auth_failed, error)])

      _ ->
        set_errors!(conn, [error(:auth_failed, "failed to retrieve access token")])
    end
  end

  @doc """
  Handles the callback from app.

  `initial_id_token` is the token that the user
  signed in successfully the first which should
  contain user status such as email.

  See https://stackoverflow.com/questions/57545635/cannot-get-name-email-with-sign-in-with-apple-on-real-device
  """
  def handle_callback!(
        %Plug.Conn{
          params: %{
            "id_token" => id_token,
            "initial_id_token" => initial_id_token,
            "name" => name
          }
        } = conn
      ) do
    with {:ok, initial_user} <- user_from_id_token(initial_id_token),
         {:ok, user} <- user_from_id_token(id_token),
         true <- initial_user["uid"] == user["uid"] do
      user =
        user
        |> Map.put("email", initial_user["email"])
        |> Map.put("name", initial_user["name"])
        |> Map.put("email_verified", initial_user["email_verified"])
        |> normalize_user_name(name)

      IO.puts "login with user, email = #{user["email"]}"

      conn
        |> put_private(:apple_user, user)
        |> put_private(:apple_token, OAuth2.AccessToken.new(id_token))
    else
      {:error, error} ->
        set_errors!(conn, [error(:auth_failed, error)])
      error ->
        set_errors!(conn, [error(:auth_failed, "failed to retrieve access token")])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"id_token" => id_token, "name" => name}} = conn) do
    case user_from_id_token(id_token) do
      {:ok, user} ->
        user = normalize_user_name(user, name)

        conn
        |> put_private(:apple_user, user)
        |> put_private(:apple_token, OAuth2.AccessToken.new(id_token))

      {:error, error} ->
        set_errors!(conn, [error(:auth_failed, error)])

      error ->
        set_errors!(conn, [error(:auth_failed, "failed to retrieve access token")])
    end
  end

  @doc false
  def handle_callback!(%Plug.Conn{params: %{"error" => error}} = conn) do
    set_errors!(conn, [error("auth_failed", error)])
  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc false
  def handle_cleanup!(conn) do
    conn
    |> put_private(:apple_user, nil)
    |> put_private(:apple_token, nil)
  end

  @doc """
  Fetches the uid field from the response.
  """
  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string

    conn.private.apple_user[uid_field]
  end

  @doc """
  Includes the credentials from the Apple response.
  """
  def credentials(conn) do
    token = conn.private.apple_token
    scope_string = token.other_params["scope"] || ""
    scopes = String.split(scope_string, ",")

    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      scopes: scopes,
      token_type: Map.get(token, :token_type),
      refresh_token: token.refresh_token,
      token: token.access_token
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """
  def info(conn) do
    user = conn.private.apple_user
    name = user["name"]

    %Info{
      email: user["email"],
      name: name && name["name"],
      first_name: name && name["firstName"],
      last_name: name && name["lastName"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the apple callback.
  """
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.apple_token,
        user: conn.private.apple_user
      }
    }
  end

  defp with_param(opts, key, conn) do
    if value = conn.params[to_string(key)], do: Keyword.put(opts, key, value), else: opts
  end

  defp with_optional(opts, key, conn) do
    if option(conn, key), do: Keyword.put(opts, key, option(conn, key)), else: opts
  end

  defp oauth_client_options_from_conn(conn) do
    base_options = [redirect_uri: callback_url(conn)]
    request_options = conn.private[:ueberauth_request_options].options

    case {request_options[:client_id], request_options[:client_secret]} do
      {nil, _} -> base_options
      {_, nil} -> base_options
      {id, secret} -> [client_id: id, client_secret: secret] ++ base_options
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp user_from_id_token(id_token) do
    with {:ok, fields} <- UeberauthApple.fields_from_id_token(id_token) do
      allowed_client_ids =
        if is_binary(@allowed_client_ids),
          do: String.split(@allowed_client_ids, ","),
          else: @allowed_client_ids || []

      if Enum.empty?(allowed_client_ids) || Enum.member?(allowed_client_ids, fields["aud"]) do
        user =
          Map.new()
          |> Map.put("uid", fields["sub"])
          |> Map.put("email", fields["email"])
          |> Map.put("name", fields["name"])
          |> Map.put("email_verified", fields["email_verified"])

        {:ok, user}
      else
        {:error,
         "Unknown client id #{fields["aud"]}, allowed client ids are #{
           inspect(allowed_client_ids)
         }"}
      end
    end
  end

  # it seems id_token doesn't include the name
  # even if we specify the scope
  defp normalize_user_name(user, name) do
    user_name = user["name"] || name || ""

    case String.split(user_name) do
      [firstName, lastName] ->
        user
        |> Map.put("name", %{
          "name" => user_name,
          "firstName" => firstName,
          "lastName" => lastName
        })

      [firstName] ->
        user
        |> Map.put("name", %{
          "name" => user_name,
          "firstName" => firstName,
          "lastName" => nil
        })

      _ ->
        user
    end
  end
end
